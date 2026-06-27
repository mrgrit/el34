"""el34 Assessor — target(별칭) → 컨테이너 해석 맵.

CC 가 보낸 check-spec 의 `target`/`container` 별칭을 docker exec 대상 컨테이너명으로
변환한다. 클라이언트는 문맥 없이(dumb) 동작 — 어떤 과목/학년/반인지 전혀 모른다.
여기 정의된 별칭은 순수하게 el34 토폴로지의 표준 호스트 이름일 뿐이다.

stdlib 만 사용 — docker/fastapi 없이 import 가능(단위 테스트 친화).
"""
from __future__ import annotations

# 표준 별칭 → (컨테이너명, dmz/토폴로지 IP). IP 는 참고용(evidence) — exec 는 컨테이너명 사용.
# el34 docker-compose.yaml 의 고정 IP 와 일치.
_TARGETS: dict[str, tuple[str, str]] = {
    # ─ 인프라 코어 ─
    "bastion":      ("el34-bastion",      "10.20.30.201"),
    "attacker":     ("el34-attacker",     "10.20.30.202"),   # ext, insider
    "attacker-ext": ("el34-attacker-ext", "10.20.20.202"),   # wan, outsider(2026-06)
    "fw":           ("el34-fw",           "10.20.30.1"),
    "ips":          ("el34-ips",          "10.20.32.1"),
    "web":          ("el34-web",          "10.20.32.80"),
    "siem":         ("el34-siem",         "10.20.32.100"),
    # ─ 취약웹 7종 (int tier) ─
    "juiceshop":    ("el34-juiceshop",    "10.20.40.81"),
    "dvwa":         ("el34-dvwa",         "10.20.40.82"),
    "neobank":      ("el34-neobank",      "10.20.40.83"),
    "govportal":    ("el34-govportal",    "10.20.40.84"),
    "mediforum":    ("el34-mediforum",    "10.20.40.85"),
    "adminconsole": ("el34-adminconsole", "10.20.40.86"),
    "aicompanion":  ("el34-aicompanion",  "10.20.40.87"),
}

# 별칭의 별칭(편의) → 표준 키. CC 가 어떤 이름으로 부르든 견고하게 해석.
_ALIASES: dict[str, str] = {
    "firewall": "fw",
    "secu": "fw",
    "el34-secu": "fw",
    "ids": "ips",
    "ips-suricata": "ips",
    "suricata": "ips",
    "waf": "web",
    "apache": "web",
    "wazuh": "siem",
    "wazuh-manager": "siem",
    "manager": "siem",
    "juice": "juiceshop",
    "admin": "adminconsole",
    "ai": "aicompanion",
    "insider": "attacker",
    "outsider": "attacker-ext",
    "attacker_ext": "attacker-ext",
}


def _normalize(name: str) -> str:
    """입력 별칭을 표준 키로 정규화. 'el34-web' 같은 컨테이너명 prefix 도 허용."""
    key = (name or "").strip().lower()
    if key.startswith("el34-"):
        # 컨테이너명 직접 지정 — prefix 제거 후 표준 키 매칭
        stripped = key[len("el34-"):]
        if stripped in _TARGETS:
            return stripped
    if key in _ALIASES:
        return _ALIASES[key]
    return key


def resolve_container(name: str) -> str:
    """별칭/타깃 → 컨테이너명. 미지원이면 KeyError(상위에서 명시적 에러로 거부)."""
    key = _normalize(name)
    if key not in _TARGETS:
        raise KeyError(f"unknown target/container: {name!r}")
    return _TARGETS[key][0]


def resolve_ip(name: str) -> str:
    key = _normalize(name)
    if key not in _TARGETS:
        raise KeyError(f"unknown target/container: {name!r}")
    return _TARGETS[key][1]


def known_targets() -> list[str]:
    """지원하는 표준 타깃 목록(정렬). /health 노출용."""
    return sorted(_TARGETS.keys())
