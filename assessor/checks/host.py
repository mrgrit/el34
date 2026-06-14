"""호스트 상태 검사 — osquery(상태 단언) 우선 + docker.sock exec(폴백/그 외).

§4.3(a): 파일/프로세스/포트 같은 상태 단언은 **osquery SQL**(read-only, 가장 안전)로
질의하고, osquery 가 없거나(attacker/취약웹) 안 되는 것(셸 빌트인·임의 텍스트·grep·
nft 등)은 docker.sock 로 고정 argv 만 exec 한다. 둘 다 부작용 0.
모든 파라미터는 화이트리스트(base.py)를 통과해야 한다.
"""
from __future__ import annotations

import json as _json
from typing import Any

from . import base
from .base import CheckError, Executor, ExecResult
from ..targets import resolve_container, resolve_ip


def _container_for(spec: dict[str, Any], default: str | None = None) -> str:
    """spec 의 target/container 별칭 → 컨테이너명. 둘 다 없으면 default."""
    name = spec.get("container") or spec.get("target") or default
    if not name:
        raise CheckError("target/container 누락")
    try:
        return resolve_container(name)
    except KeyError as e:
        raise CheckError(str(e))


# ─── osquery 헬퍼 (read-only SQL) ────────────────────────────────────────────
def _sql_lit(s: str) -> str:
    """SQL 문자열 리터럴 — 작은따옴표 이스케이프(osquery 는 read-only 라 주입해도 write 불가)."""
    return "'" + str(s).replace("'", "''") + "'"


def _osquery(ex: Executor, container: str, sql: str):
    """osqueryi --json 실행 → rows(list[dict]). osquery 미설치/실패면 None(→ 폴백)."""
    r = ex.exec(container, ["osqueryi", "--json", sql])
    if r.exit_code != 0 or not r.stdout.strip():
        # exit 0 + 빈 결과는 "[]" 를 내므로, 빈 stdout 은 osqueryi 부재(127 등)로 간주
        if r.exit_code != 0:
            return None
    try:
        return _json.loads(r.stdout or "[]")
    except Exception:
        return None


# ─── file_exists {path, container} ───────────────────────────────────────────
def file_exists(spec, ex: Executor):
    p = spec["params"]
    path = base.validate_path(p.get("path"))
    cont = _container_for(spec)
    # (i) osquery 우선 — file 테이블(read-only SQL). path 는 [A-Za-z0-9._-/] 만 허용돼 주입 불가.
    rows = _osquery(ex, cont, f"SELECT path, size, mtime FROM file WHERE path={_sql_lit(path)}")
    if rows is not None:
        passed = len(rows) > 0
        ev = (f"{rows[0].get('path')}|size={rows[0].get('size')}|mtime={rows[0].get('mtime')}"
              if passed else f"not found: {path}")
        return base.ok(spec["id"], passed, ev, {"engine": "osquery", "container": cont})
    # (ii) 폴백 — docker.sock stat
    r = ex.exec(cont, ["stat", "-c", "%n|size=%s|mtime=%y", "--", path])
    passed = r.exit_code == 0
    ev = r.stdout.strip() if passed else f"not found: {path}"
    return base.ok(spec["id"], passed, ev, {"engine": "exec", "exit_code": r.exit_code, "container": cont})


# ─── file_contains {path, pattern|regex, container} ──────────────────────────
def file_contains(spec, ex: Executor):
    p = spec["params"]
    path = base.validate_path(p.get("path"))
    cont = _container_for(spec)
    if p.get("regex") is not None:
        pat = base.validate_pattern(p.get("regex"), "regex")
        mode = "-E"           # 확장 정규식
    else:
        pat = base.validate_pattern(p.get("pattern"), "pattern")
        mode = "-F"           # 고정 문자열
    # grep -n -m1: 첫 매치 라인(번호 포함) = evidence. exit 0 = 매치.
    r = ex.exec(cont, ["grep", mode, "-n", "-m", "1", "-e", pat, "--", path])
    passed = r.exit_code == 0
    ev = r.stdout.strip() if passed else f"no match for {pat!r} in {path}"
    return base.ok(spec["id"], passed, ev, {"exit_code": r.exit_code, "container": cont})


# ─── file_hash {path, container, sha256?} ────────────────────────────────────
def file_hash(spec, ex: Executor):
    p = spec["params"]
    path = base.validate_path(p.get("path"))
    cont = _container_for(spec)
    r = ex.exec(cont, ["sha256sum", "--", path])
    if r.exit_code != 0:
        return base.ok(spec["id"], False, f"hash 실패(파일 없음?): {path}",
                       {"exit_code": r.exit_code, "container": cont})
    digest = r.stdout.strip().split()[0] if r.stdout.strip() else ""
    expected = p.get("sha256") or p.get("expected")
    if expected:
        expected = base.validate_pattern(str(expected), "sha256")
        passed = digest.lower() == expected.lower()
        ev = f"sha256={digest} expected={expected} match={passed}"
    else:
        passed = bool(digest)
        ev = f"sha256={digest}"
    return base.ok(spec["id"], passed, ev, {"sha256": digest, "container": cont})


# ─── process_running {name|pattern, container} ───────────────────────────────
def process_running(spec, ex: Executor):
    p = spec["params"]
    value = p.get("pattern") or p.get("name")
    pat = base.validate_pattern(value, "name|pattern")
    if pat.startswith("-"):
        raise CheckError("name|pattern 은 '-' 로 시작 불가")
    cont = _container_for(spec)
    # (i) osquery 우선 — processes 테이블(name/cmdline LIKE). read-only.
    # ★ osqueryi 자기 프로세스 제외 — 질의 SQL 에 pat 이 들어가 cmdline 에 self-match 되는
    #   false positive 방지(name != 'osqueryi').
    like = _sql_lit(f"%{pat}%")
    rows = _osquery(ex, cont,
                    f"SELECT pid, name, cmdline FROM processes "
                    f"WHERE (cmdline LIKE {like} OR name LIKE {like}) "
                    f"AND name != 'osqueryi' LIMIT 5")
    if rows is not None:
        passed = len(rows) > 0
        ev = (f"pid={rows[0].get('pid')} {rows[0].get('name')}: {rows[0].get('cmdline','')[:120]}"
              if passed else f"no process matching {pat!r}")
        return base.ok(spec["id"], passed, ev, {"engine": "osquery", "container": cont})
    # (ii) 폴백 — docker.sock pgrep
    r = ex.exec(cont, ["pgrep", "-a", "-f", pat])
    passed = r.exit_code == 0
    ev = r.stdout.strip() if passed else f"no process matching {pat!r}"
    return base.ok(spec["id"], passed, ev, {"engine": "exec", "exit_code": r.exit_code, "container": cont})


# ─── port_listening {port, container} ────────────────────────────────────────
def port_listening(spec, ex: Executor):
    p = spec["params"]
    port = base.validate_port(p.get("port"))
    cont = _container_for(spec)
    # (i) osquery 우선 — listening_ports 테이블. port 는 정수 검증됨.
    rows = _osquery(ex, cont,
                    f"SELECT port, protocol, address FROM listening_ports WHERE port={port}")
    if rows is not None:
        passed = len(rows) > 0
        ev = (f"listening :{port} proto={rows[0].get('protocol')} addr={rows[0].get('address')}"
              if passed else f"port {port} not listening")
        return base.ok(spec["id"], passed, ev,
                       {"engine": "osquery", "container": cont, "matches": len(rows)})
    # (ii) 폴백 — docker.sock ss -ltn
    r = ex.exec(cont, ["ss", "-ltn"])
    matched = []
    for ln in r.stdout.splitlines():
        cols = ln.split()
        # ss 출력: State Recv-Q Send-Q Local Local:Port Peer ...
        for col in cols:
            if col.rsplit(":", 1)[-1] == str(port) and ":" in col:
                matched.append(ln.strip())
                break
    passed = bool(matched)
    ev = matched[0] if passed else f"port {port} not listening"
    return base.ok(spec["id"], passed, ev, {"engine": "exec", "container": cont, "matches": len(matched)})


# ─── log_contains {log, pattern, since_sec?, container?} ─────────────────────
# 로그 별칭 → (컨테이너 기본값, 경로). auth 는 container 파라미터 필요.
_LOG_MAP = {
    "suricata":     ("ips", "/var/log/suricata/eve.json"),
    "modsec":       ("web", "/var/log/apache2/modsec_audit.log"),
    "apache_error": ("web", "/var/log/apache2/error.log"),
    "auth":         (None,  "/var/log/auth.log"),
}


def log_contains(spec, ex: Executor):
    p = spec["params"]
    log = p.get("log")
    if log not in _LOG_MAP:
        raise CheckError(f"미지원 log 별칭: {log!r} (지원: {sorted(_LOG_MAP)})")
    pat = base.validate_pattern(p.get("pattern"), "pattern")
    default_cont, path = _LOG_MAP[log]
    cont = _container_for(spec, default=default_cont)
    # tail 로 최근 라인만 read-only 로 가져와 python 에서 매칭(주입 면역).
    r = ex.exec(cont, ["tail", "-n", "4000", path])
    import re as _re
    try:
        rx = _re.compile(pat)
    except _re.error:
        # 정규식 컴파일 실패 시 고정 문자열 매칭으로 fallback
        rx = None
    hits = []
    for ln in r.stdout.splitlines():
        if (rx.search(ln) if rx else (pat in ln)):
            hits.append(ln)
    passed = bool(hits)
    ev = hits[-1] if passed else f"no log line matching {pat!r} in {log}"
    return base.ok(spec["id"], passed, ev,
                   {"container": cont, "path": path, "matches": len(hits)})


HANDLERS = {
    "file_exists":     file_exists,
    "file_contains":   file_contains,
    "file_hash":       file_hash,
    "process_running": process_running,
    "port_listening":  port_listening,
    "log_contains":    log_contains,
}
