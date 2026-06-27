"""el34 Assessor — FastAPI 진입점.

POST /assess  (X-API-Key)  : CC 의 check-spec → 읽기 전용 검사 → pass/fail + 근거
GET  /health               : 헬스 + 지원 type/target 목록(인증 불필요)

마운트(read-only): /var/run/docker.sock, wazuh-manager-logs, ips-suricata-logs,
web-apache-logs — portal 과 동일 access 패턴.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .activity import WANT_ALL, build_activity
from .checks import SUPPORTED_TYPES, run_check
from .checks.base import ExecResult
from .targets import known_targets

VERSION = "1.1.0"   # v2: /activity 모니터링 피드 + auditd 명령 수집 추가
API_KEY = os.getenv("API_KEY", "ccc-api-key-2026")
ALERTS_PATH = Path(os.getenv("ALERTS_PATH", "/data/wazuh/alerts/alerts.json"))
EXEC_TIMEOUT = int(os.getenv("EXEC_TIMEOUT", "15"))

# 풍부 경로(옵션): Wazuh indexer 질의. 기본은 alerts.json(견고·무의존).
USE_INDEXER = os.getenv("USE_INDEXER", "0") == "1"
INDEXER_URL = os.getenv("INDEXER_URL", "https://10.20.32.110:9200")
INDEXER_USER = os.getenv("INDEXER_USER", "admin")
INDEXER_PASS = os.getenv("INDEXER_PASS", "SecretPassword")

app = FastAPI(title="el34 Assessor", docs_url="/api/docs", redoc_url=None)


# ─── 인증: X-API-Key ─────────────────────────────────────────────────────────
def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# ─── Executor: docker.sock 로 read-only argv exec ────────────────────────────
class DockerExecutor:
    def __init__(self) -> None:
        # lazy 연결 — docker.sock 이 import 시점에 준비 안 돼도 startup crash 안 함.
        self._cli = None

    def _client(self):
        if self._cli is None:
            self._cli = docker.DockerClient(base_url="unix:///var/run/docker.sock")
        return self._cli

    def exec(self, container: str, argv: list[str], timeout: int = EXEC_TIMEOUT) -> ExecResult:
        # cmd 를 list 로 전달 → docker 가 셸 없이 직접 실행(주입 면역).
        try:
            c = self._client().containers.get(container)
        except docker.errors.NotFound:
            return ExecResult(127, "", f"container not found: {container}")
        except Exception as e:  # noqa: BLE001
            return ExecResult(126, "", f"docker error: {e}")
        try:
            res = c.exec_run(cmd=argv, stdout=True, stderr=True, demux=True, tty=False)
            out, errb = (res.output if isinstance(res.output, tuple) else (res.output, b""))
            return ExecResult(
                res.exit_code if res.exit_code is not None else -1,
                (out or b"").decode("utf-8", "replace"),
                (errb or b"").decode("utf-8", "replace"),
            )
        except Exception as e:  # noqa: BLE001
            return ExecResult(-1, "", f"exec error: {e}")


# ─── AlertSource: 로컬 alerts.json (+ 옵션 indexer) ──────────────────────────
def _parse_ts(ts: str) -> float | None:
    if not ts:
        return None
    try:
        # "2026-06-03T12:00:00.123+0000" → fromisoformat 호환으로 정규화
        t = ts.replace("Z", "+00:00")
        if len(t) >= 5 and (t[-5] in "+-") and t[-3] != ":":
            t = t[:-2] + ":" + t[-2:]   # +0000 → +00:00
        return datetime.fromisoformat(t).timestamp()
    except Exception:
        try:
            return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=timezone.utc).timestamp()
        except Exception:
            return None


def _tail_lines(path: Path, n: int = 6000) -> list[str]:
    if not path.exists():
        return []
    try:
        with path.open("rb") as f:
            f.seek(0, 2)
            size = f.tell()
            chunk = min(size, 4 * 1024 * 1024)   # 최근 4MB
            f.seek(-chunk, 2)
            data = f.read().decode("utf-8", "replace")
        return data.splitlines()[-n:]
    except Exception:
        return []


class AlertSource:
    """wazuh-manager-logs 마운트의 alerts.json 을 읽어 since_sec 필터."""

    def alerts(self, since_sec: int | None = None) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        cutoff = None
        if since_sec:
            cutoff = datetime.now(timezone.utc).timestamp() - float(since_sec)
        for line in _tail_lines(ALERTS_PATH):
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line)
            except Exception:
                continue
            if cutoff is not None:
                ts = _parse_ts(a.get("timestamp", ""))
                if ts is not None and ts < cutoff:
                    continue
            out.append(a)
        if USE_INDEXER:
            out.extend(self._indexer_alerts(since_sec))
        return out

    def _indexer_alerts(self, since_sec: int | None) -> list[dict[str, Any]]:
        # 풍부 경로(옵션) — self-signed → verify off. 실패해도 alerts.json 결과는 유지.
        try:
            import httpx
            gte = f"now-{int(since_sec)}s" if since_sec else "now-24h"
            query = {
                "size": 2000,
                "sort": [{"timestamp": {"order": "desc"}}],
                "query": {"range": {"timestamp": {"gte": gte}}},
            }
            with httpx.Client(verify=False, timeout=5.0) as cli:
                r = cli.post(f"{INDEXER_URL}/wazuh-alerts-*/_search",
                             auth=(INDEXER_USER, INDEXER_PASS), json=query)
                hits = r.json().get("hits", {}).get("hits", [])
                return [h.get("_source", {}) for h in hits]
        except Exception:
            return []


_executor = DockerExecutor()
_alerts = AlertSource()


# ─── routes ──────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> JSONResponse:
    # wazuh_reachable: 로컬 alerts.json 읽기 가능(간단경로) 또는 indexer 도달(풍부경로)
    wazuh_reachable = ALERTS_PATH.exists()
    if not wazuh_reachable and USE_INDEXER:
        wazuh_reachable = _indexer_reachable()
    return JSONResponse({
        "status": "ok",
        "service": "el34-assessor",
        "hostname": os.uname().nodename,
        "version": VERSION,
        "wazuh_reachable": wazuh_reachable,
        "time": datetime.now(timezone.utc).isoformat(),
        "surfaces": ["/assess", "/activity"],
        "supported_types": SUPPORTED_TYPES,
        "targets": known_targets(),
        "alerts_source": str(ALERTS_PATH),
        "indexer_enabled": USE_INDEXER,
    })


def _indexer_reachable() -> bool:
    try:
        import httpx
        with httpx.Client(verify=False, timeout=2.0) as cli:
            r = cli.get(f"{INDEXER_URL}", auth=(INDEXER_USER, INDEXER_PASS))
            return r.status_code < 500
    except Exception:
        return False


@app.post("/activity", dependencies=[Depends(require_api_key)])
async def activity(payload: dict[str, Any]) -> JSONResponse:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="body must be a JSON object")
    want = payload.get("want") or WANT_ALL
    if isinstance(want, str):
        want = [want]
    bad = [w for w in want if w not in WANT_ALL]
    if bad:
        raise HTTPException(status_code=400, detail=f"unknown 'want' items: {bad} (valid: {WANT_ALL})")
    out = build_activity(payload, _executor, _alerts)
    out["collected_at"] = datetime.now(timezone.utc).isoformat()
    return JSONResponse(out)


@app.post("/assess", dependencies=[Depends(require_api_key)])
async def assess(payload: dict[str, Any]) -> JSONResponse:
    checks = payload.get("checks")
    if not isinstance(checks, list):
        raise HTTPException(status_code=400, detail="'checks' must be a list")
    if len(checks) > 200:
        raise HTTPException(status_code=400, detail="too many checks (max 200)")

    results = []
    for spec in checks:
        if not isinstance(spec, dict):
            results.append({"id": "?", "passed": None, "evidence": "",
                            "error": "check must be an object", "raw": {}})
            continue
        results.append(run_check(spec, _executor, _alerts))

    return JSONResponse({
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "battle_id": payload.get("battle_id"),
        "results": results,
    })
