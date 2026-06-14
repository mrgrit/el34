"""6v6 Assessor — check 핸들러 공용 기반.

핵심 보안 원칙(절대 위반 금지):
  CC 가 보낸 문자열을 **절대 셸로 해석하지 않는다**. 모든 호스트 검사는
  고정 명령 템플릿(리스트 형태 argv) + 파라미터 화이트리스트로만 합성한다.
  docker exec 는 셸 없이 argv 를 직접 실행(shell=False 등가) → 메타문자 주입 무효.
  미지원 type / 위험 파라미터는 passed:false 가 아니라 명시적 CheckError 로 거부.

stdlib 만 사용 — 단위 테스트 시 docker/fastapi 불필요.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol


# ─── 에러: 미지원/위험 요청은 명시적으로 거부(passed:false 아님) ────────────────
class CheckError(Exception):
    """검사를 수행할 수 없음(잘못된 type/파라미터/위험 패턴). 결과의 error 필드로 노출."""


# ─── exec 결과 + executor 프로토콜(테스트 시 fake 주입) ──────────────────────
@dataclass
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str


class Executor(Protocol):
    """컨테이너 안에서 read-only argv 를 실행. 실제 구현은 docker SDK(app.py)."""

    def exec(self, container: str, argv: list[str], timeout: int = 15) -> ExecResult: ...


class AlertSource(Protocol):
    """로컬 Wazuh alerts.json 질의(읽기 전용). 실제 구현은 app.py."""

    def alerts(self, since_sec: int | None = None) -> list[dict[str, Any]]: ...


# ─── 파라미터 화이트리스트(엄격) ─────────────────────────────────────────────
# 절대경로: 영문/숫자/ . _ - / 만. 셸 메타문자(; | & $ ` 공백 등) 전면 금지.
_PATH_RE = re.compile(r"^/[A-Za-z0-9._\-/]{0,512}$")
# 프로세스/파일 패턴(grep/pgrep 인자): 정규식 메타는 허용하되 셸 메타·NUL 금지.
# argv 로 전달되므로 셸 주입은 불가하지만, 방어적으로 위험 제어문자 차단.
_DANGEROUS_CHARS = re.compile(r"[\x00-\x1f`]")
# 로그 별칭 화이트리스트
LOG_ALIASES = {"suricata", "modsec", "apache_error", "auth"}

EVIDENCE_MAX = 2048   # 응답 evidence 는 <=2KB (계약)


def validate_path(path: Any) -> str:
    if not isinstance(path, str) or not path:
        raise CheckError("path 누락 또는 형식 오류")
    if not _PATH_RE.match(path):
        raise CheckError(f"허용되지 않는 path(절대경로 + [A-Za-z0-9._-/] 만): {path!r}")
    if ".." in path:
        raise CheckError(f"경로 traversal('..') 금지: {path!r}")
    return path


def validate_pattern(pattern: Any, field: str = "pattern") -> str:
    if not isinstance(pattern, str) or pattern == "":
        raise CheckError(f"{field} 누락")
    if len(pattern) > 512:
        raise CheckError(f"{field} 과도하게 김(>512)")
    if _DANGEROUS_CHARS.search(pattern):
        raise CheckError(f"{field} 에 제어문자 포함 — 거부")
    return pattern


def validate_port(port: Any) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise CheckError(f"port 정수 아님: {port!r}")
    if not (1 <= p <= 65535):
        raise CheckError(f"port 범위 밖(1-65535): {p}")
    return p


def validate_name(name: Any, field: str = "name") -> str:
    if not isinstance(name, str) or not name:
        raise CheckError(f"{field} 누락")
    if len(name) > 256 or _DANGEROUS_CHARS.search(name):
        raise CheckError(f"{field} 형식 오류")
    return name


def clip(text: str, n: int = EVIDENCE_MAX) -> str:
    if text is None:
        return ""
    text = str(text)
    return text if len(text) <= n else text[:n] + "…(truncated)"


def ok(check_id: str, passed: bool, evidence: str = "", raw: dict | None = None) -> dict[str, Any]:
    return {
        "id": check_id,
        "passed": bool(passed),
        "evidence": clip(evidence),
        "raw": raw or {},
    }


def err(check_id: str, message: str, raw: dict | None = None) -> dict[str, Any]:
    """명시적 거부/실패 — passed 는 None(불가) 으로 두고 error 노출."""
    return {
        "id": check_id,
        "passed": None,
        "evidence": "",
        "error": clip(message, 512),
        "raw": raw or {},
    }
