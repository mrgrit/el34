"""el34 (옵션) 룰 무장 provisioner — §8-3.

★ 기본 비활성(`SKIP_PROVISIONER=1`, compose profile `provisioner` 미활성). Assessor 와
  **분리된 별도 write 서비스**다. read-only 원칙의 유일한 예외로, tubewar 가 미션 시작 시
  검증된 룰 템플릿을 무장(provision)하고 종료 시 회수(revoke)한다.

안전장치:
  - CC 가 raw 룰 텍스트를 보내지 않는다. **named 템플릿 화이트리스트** + 파라미터 검증만.
  - sid 는 provisioner 가 9000000+ 슬롯에서 할당(학생/기존 룰과 충돌 방지).
  - write 대상은 manager 의 전용 파일 `/var/ossec/etc/rules/el34-provisioned-rules.xml`
    하나로 한정(다른 룰/디코더 불변). revoke 로 깔끔히 제거.
  - 토폴로지·Suricata·취약웹·Bastion 불변. 결합·상태 트레이드오프는 ASSESSOR.md §8 에 기록.
"""
from __future__ import annotations

import base64
import os
import re
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from .app import DockerExecutor  # 동일 docker.sock exec 메커니즘 재사용

API_KEY = os.getenv("API_KEY", "ccc-api-key-2026")
VERSION = "1.1.0"
SIEM = "el34-siem"
# ★ 'zz-' prefix — Wazuh 는 etc/rules/*.xml 를 알파벳 순으로 로드하므로, if_sid(100260)/
#   if_group(syscheck) 참조 대상이 먼저 로드되도록 provisioned 파일을 **마지막**에 로드시킨다.
RULES_FILE = "/var/ossec/etc/rules/zz-el34-provisioned-rules.xml"
# ★ Wazuh rule id 는 최대 6자리(≤999999). 기존 el34 커스텀(100200-100261)과 떨어진
#   110000-119999 를 provisioner 전용 슬롯으로 쓴다. (Suricata sid≥9000000 슬롯과 무관.)
SID_BASE = 110000
SID_MAX = 119999

app = FastAPI(title="el34 Provisioner (옵션·write)", docs_url="/api/docs", redoc_url=None)
_ex = DockerExecutor()


def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid or missing X-API-Key")


# ─── 파라미터 검증(화이트리스트) ─────────────────────────────────────────────
_LABEL_RE = re.compile(r"^[A-Za-z0-9 _.\-:#]{1,80}$")
_PCRE_SAFE = re.compile(r"^[A-Za-z0-9 _.\-/:%?=&|()\[\]{}^$*+\\]{1,200}$")  # 룰 pcre2 용 제한 문자


def _v_label(s):
    if not isinstance(s, str) or not _LABEL_RE.match(s):
        raise HTTPException(422, "label 형식 오류([A-Za-z0-9 _.-:#], ≤80)")
    return s


def _v_pattern(s):
    if not isinstance(s, str) or not _PCRE_SAFE.match(s):
        raise HTTPException(422, "pattern 형식 오류(제한 문자셋, ≤200)")
    # XML/룰 안전: 꺾쇠·따옴표 차단(템플릿 구조 보호)
    if any(c in s for c in '<>"'):
        raise HTTPException(422, "pattern 에 < > \" 사용 불가")
    return s


# ─── 템플릿 화이트리스트 — named 템플릿만, 파라미터 슬롯 검증 ─────────────────
# 각 템플릿: params → Wazuh local rule XML(한 룰). MY cmdlog/syscheck 디코더 필드 위에 동작.
def _tpl_command(sid, params):
    label = _v_label(params.get("label", "mission"))
    patt = _v_pattern(params.get("pattern", ""))
    level = int(params.get("level", 10))
    level = max(1, min(15, level))
    return (f'  <rule id="{sid}" level="{level}">\n'
            f'    <if_sid>100260</if_sid>\n'
            f'    <field name="command" type="pcre2">{patt}</field>\n'
            f'    <description>el34 무장: {label} — cmd $(command) by $(cmd_user)@$(cmd_host)</description>\n'
            f'    <group>el34,provisioned,cmdlog,</group>\n'
            f'  </rule>\n')


def _tpl_fim(sid, params):
    label = _v_label(params.get("label", "mission"))
    patt = _v_pattern(params.get("path_pattern", ""))
    level = int(params.get("level", 10))
    level = max(1, min(15, level))
    return (f'  <rule id="{sid}" level="{level}">\n'
            f'    <if_group>syscheck</if_group>\n'
            f'    <field name="file" type="pcre2">{patt}</field>\n'
            f'    <description>el34 무장: {label} — FIM 변경 $(file)</description>\n'
            f'    <group>el34,provisioned,syscheck,</group>\n'
            f'  </rule>\n')


TEMPLATES = {
    "alert_command_pattern": _tpl_command,   # 특정 명령 패턴 실행 시 경보(cmdlog 디코더 기반)
    "alert_fim_path": _tpl_fim,              # 특정 경로 FIM 변경 시 경보
}


# ─── 파일 read/write (docker.sock exec, base64 로 안전 전송) ──────────────────
def _read_rules() -> str:
    r = _ex.exec(SIEM, ["cat", RULES_FILE])
    return r.stdout if r.exit_code == 0 else ""


def _write_rules_and_reload(body: str) -> tuple[bool, str]:
    """전용 파일에만 write 후 analysisd -t 로 **검증**하고, 통과 시에만 restart.
    검증 실패 시 백업 복원(롤백) — 잘못된 템플릿이 실행 중 manager 를 절대 깨지 못하게 한다.
    b64 전송이라 셸 주입 불가."""
    b64 = base64.b64encode(body.encode()).decode()
    script = (
        f'F={RULES_FILE}; B=/tmp/el34-prov.bak; HAD=1\n'
        f'if [ -f "$F" ]; then cp "$F" "$B"; else HAD=0; fi\n'
        f'echo {b64} | base64 -d > "$F"\n'
        f'chown root:wazuh "$F" 2>/dev/null; chmod 660 "$F" 2>/dev/null\n'
        f'if /var/ossec/bin/wazuh-analysisd -t >/tmp/el34-prov-test.log 2>&1; then\n'
        f'  /var/ossec/bin/wazuh-control restart >/tmp/el34-prov-reload.log 2>&1; echo PROV_OK\n'
        f'else\n'
        f'  if [ "$HAD" = 1 ]; then cp "$B" "$F"; else rm -f "$F"; fi\n'
        f'  echo PROV_TESTFAIL; tail -3 /tmp/el34-prov-test.log\n'
        f'fi\n'
        f'rm -f "$B"\n'
    )
    r = _ex.exec(SIEM, ["sh", "-c", script], timeout=90)
    ok = "PROV_OK" in r.stdout
    return ok, (r.stdout + r.stderr).strip()[:400]


def _remove_rules_and_reload() -> tuple[bool, str]:
    """무장 룰이 0개가 되면 빈 <group>(Wazuh 가 거부) 대신 파일을 **삭제**하고 reload."""
    r = _ex.exec(SIEM, ["sh", "-c",
                        f"rm -f {RULES_FILE}; /var/ossec/bin/wazuh-control restart "
                        f">/tmp/el34-prov-reload.log 2>&1; echo PROV_OK"], timeout=90)
    return ("PROV_OK" in r.stdout), (r.stdout + r.stderr).strip()[:300]


def _wrap(rules: dict[int, str]) -> str:
    inner = "".join(rules[s] for s in sorted(rules))
    return ('<!-- el34 provisioned rules (provisioner 가 관리 — 수동 편집 금지) -->\n'
            '<group name="el34,provisioned,">\n' + inner + '</group>\n')


def _parse_existing() -> dict[int, str]:
    """현재 파일에서 sid→룰블록 파싱(revoke/중복관리용)."""
    out: dict[int, str] = {}
    txt = _read_rules()
    for m in re.finditer(r'(  <rule id="(\d+)".*?</rule>\n)', txt, re.DOTALL):
        out[int(m.group(2))] = m.group(1)
    return out


# ─── routes ──────────────────────────────────────────────────────────────────
@app.get("/health")
def health() -> JSONResponse:
    return JSONResponse({
        "status": "ok", "service": "el34-provisioner", "version": VERSION,
        "hostname": os.uname().nodename, "write_enabled": True,
        "templates": sorted(TEMPLATES), "rules_file": RULES_FILE,
        "active_sids": sorted(_parse_existing()),
    })


@app.post("/provision-rule", dependencies=[Depends(require_api_key)])
async def provision(payload: dict[str, Any]) -> JSONResponse:
    tpl = payload.get("template")
    if tpl not in TEMPLATES:
        raise HTTPException(422, f"미지원 template: {tpl!r} (화이트리스트: {sorted(TEMPLATES)})")
    params = payload.get("params") or {}
    if not isinstance(params, dict):
        raise HTTPException(422, "params 는 object")
    existing = _parse_existing()
    # 다음 sid 할당(110000-119999 슬롯)
    sid = max([SID_BASE - 1, *existing.keys()]) + 1 if existing else SID_BASE
    if sid > SID_MAX:
        raise HTTPException(507, f"provisioner sid 슬롯 소진(>{SID_MAX}) — revoke 필요")
    rule_xml = TEMPLATES[tpl](sid, params)
    existing[sid] = rule_xml
    ok, log = _write_rules_and_reload(_wrap(existing))
    if not ok:
        raise HTTPException(500, f"룰 반영 실패: {log}")
    return JSONResponse({"provisioned": True, "sid": sid, "template": tpl,
                         "provisioned_at": datetime.now(timezone.utc).isoformat()})


@app.post("/revoke-rule", dependencies=[Depends(require_api_key)])
async def revoke(payload: dict[str, Any]) -> JSONResponse:
    sid = payload.get("sid")
    try:
        sid = int(sid)
    except (TypeError, ValueError):
        raise HTTPException(422, "sid(int) 필요")
    existing = _parse_existing()
    if sid not in existing:
        return JSONResponse({"revoked": False, "reason": "해당 sid 없음", "sid": sid})
    del existing[sid]
    if existing:
        ok, log = _write_rules_and_reload(_wrap(existing))
    else:
        # 남은 룰 0개 → 빈 group 은 Wazuh 가 거부하므로 파일 삭제로 회수
        ok, log = _remove_rules_and_reload()
    if not ok:
        raise HTTPException(500, f"회수 반영 실패: {log}")
    return JSONResponse({"revoked": True, "sid": sid,
                         "remaining": sorted(existing)})
