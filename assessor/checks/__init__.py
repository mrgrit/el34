"""check 핸들러 dispatch.

호스트 검사(host.*)는 Executor(docker.sock exec)를, 보안 알림 검사(wazuh.*)는
AlertSource(alerts.json)를 받는다. run_check 가 type 에 맞는 핸들러로 위임한다.
미지원 type 은 명시적 에러로 거부(passed:false 아님).
"""
from __future__ import annotations

from typing import Any

from . import base, host, wazuh
from .base import CheckError

_HOST = host.HANDLERS
_WAZUH = wazuh.HANDLERS
SUPPORTED_TYPES = sorted(list(_HOST) + list(_WAZUH))


def run_check(spec: dict[str, Any], executor, alert_source) -> dict[str, Any]:
    """단일 check-spec 실행 → 결과 dict. 어떤 예외도 결과로 흡수(요청 전체는 200)."""
    cid = spec.get("id") or "?"
    ctype = spec.get("type")
    # params 없으면 빈 dict 로 보정
    if "params" not in spec or spec["params"] is None:
        spec = {**spec, "params": {}}
    try:
        if ctype in _HOST:
            return _HOST[ctype](spec, executor)
        if ctype in _WAZUH:
            return _WAZUH[ctype](spec, alert_source)
        raise CheckError(f"미지원 check type: {ctype!r} (지원: {SUPPORTED_TYPES})")
    except CheckError as e:
        return base.err(cid, str(e), {"type": ctype})
    except KeyError as e:
        return base.err(cid, f"필수 파라미터 누락: {e}", {"type": ctype})
    except Exception as e:  # noqa: BLE001 — 핸들러 내부 예기치 못한 오류도 결과로 흡수
        return base.err(cid, f"검사 실행 오류: {type(e).__name__}: {e}", {"type": ctype})
