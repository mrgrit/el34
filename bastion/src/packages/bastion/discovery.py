"""Bastion Infrastructure Discovery — 인프라/자산 자동 발견 (Phase B).

목적: bastion 을 특정 배포(el34)에 묶지 않고 **범용**으로. 부팅 시(또는 POST /discover)
호스트의 docker 인프라를 스캔해 컨테이너·서비스·역할을 파악하고:
  1) 역할 → 컨테이너 매핑을 만들어 targets.resolve_target 가 사용(하드코딩 el34 대체),
  2) 자산을 KG(asset_domain)에 등록해 페르소나 도출/아키텍처 분석의 기반으로 삼는다.

발견 경로
---------
- 1차(주): bastion 의 docker.sock 으로 `docker ps`(+옵션 inspect) — 가장 정확.
- (후속) 2차: probe_all/probe_host 로 SubAgent 도달 호스트 보강.

역할 추론(infer_role): 컨테이너 이름 + 이미지 키워드 휴리스틱. 구체적 → 일반 순서로
매칭하며, 같은 역할은 첫 매칭을 채택. 추론 실패/모호 시 targets 의 정적 el34 폴백이
안전망이 되므로 el34 동작은 깨지지 않는다.

활성화: 환경변수 `BASTION_DISCOVERY=1`. 미설정 시 discovery 는 호출돼도 매핑을
적용하지 않고(targets 가 정적 폴백 사용) 기존 동작과 동일.
"""
from __future__ import annotations

import os
import threading

from bastion import run_command

# 발견된 역할 → 컨테이너 매핑(런타임 캐시). targets.get_discovered_container 가 조회.
_DISCOVERED: dict[str, str] = {}
_LOCK = threading.Lock()

# 역할 추론 휴리스틱 — (키워드 튜플, 역할). 구체적 → 일반 순서 (앞이 우선).
# 이름/이미지 문자열에 키워드가 포함되면 매칭.
_ROLE_HINTS: list[tuple[tuple[str, ...], str]] = [
    (("wazuh-indexer", "opensearch", "elasticsearch", "indexer"), "indexer"),
    (("wazuh-dashboard", "dashboard", "kibana"), "dashboard"),
    (("suricata", "snort", "-ips", "_ips", "/ips"), "ids"),
    (("wazuh-manager", "wazuh.manager", "-siem", "_siem", "ossec", "siem"), "siem"),
    (("modsec", "modsecurity", "-waf", "waf", "-web", "_web", "apache", "httpd", "nginx"), "web"),
    (("nftables", "firewall", "-fw", "_fw", "iptables"), "fw"),
    (("attacker", "kali", "metasploit", "pentest"), "attacker"),
    (("ollama", "vllm", "llm-", "-llm"), "ai-model"),
    (("misp",), "misp"),
    (("opencti", "connector-", "worker"), "cti"),
    (("portal",), "portal"),
    (("juiceshop", "dvwa", "neobank", "govportal", "mediforum", "adminconsole",
      "aicompanion"), "app"),
    (("bastion",), "bastion"),
]


def infer_role(name: str, image: str = "", labels: str = "") -> str | None:
    """컨테이너 이름/이미지/라벨에서 서비스 역할 추론(없으면 None)."""
    hay = f" {name} {image} {labels} ".lower()
    for kws, role in _ROLE_HINTS:
        if any(k in hay for k in kws):
            return role
    return None


def discover_infra(vm_ips: dict[str, str] | None = None,
                   register_assets: bool = True) -> dict:
    """docker ps 로 인프라 스캔 → 역할맵 빌드 + (옵션)자산 등록. 멱등.

    반환: {containers:[{name,image,role,status,ports}], role_map:{role:container}, count}.
    BASTION_DISCOVERY 와 무관하게 스캔/등록은 수행하되, 매핑 적용(targets 사용)은
    환경변수가 켜진 경우에만 targets 가 참조한다.
    """
    vm_ips = vm_ips or {}
    bastion_ip = vm_ips.get("bastion") or "127.0.0.1"
    fmt = "{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"
    r = run_command(bastion_ip, f"docker ps --format '{fmt}'", timeout=20)
    out = r.get("stdout", "") or r.get("output", "")

    containers: list[dict] = []
    role_map: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        parts = line.split("|")
        name = parts[0].strip()
        image = parts[1].strip() if len(parts) > 1 else ""
        status = parts[2].strip() if len(parts) > 2 else ""
        ports = parts[3].strip() if len(parts) > 3 else ""
        role = infer_role(name, image)
        containers.append({"name": name, "image": image, "role": role,
                           "status": status, "ports": ports})
        if role and role not in role_map:   # 같은 역할은 첫 매칭 채택
            role_map[role] = name

    with _LOCK:
        _DISCOVERED.clear()
        _DISCOVERED.update(role_map)

    if register_assets:
        _persist_assets(containers, role_map)

    return {"containers": containers, "role_map": role_map, "count": len(containers)}


def get_discovered_container(role: str) -> str | None:
    """발견된 역할 → 컨테이너(없으면 None). targets.container_for 가 호출."""
    with _LOCK:
        return _DISCOVERED.get(role)


def discovered_map() -> dict[str, str]:
    with _LOCK:
        return dict(_DISCOVERED)


def _persist_assets(containers: list[dict], role_map: dict[str, str]) -> None:
    """발견 컨테이너를 KG 자산으로 등록 + infra-map 노드 기록(멱등, silent)."""
    try:
        from bastion.asset_domain import register_asset
        for c in containers:
            register_asset(
                asset_id=f"asset:container:{c['name']}",
                name=c["name"], kind="host",
                services=[c["role"]] if c.get("role") else [],
                meta={"image": c["image"], "role": c.get("role"),
                      "status": c["status"], "ports": c["ports"],
                      "source": "discovery"},
            )
    except Exception:
        pass
    try:
        from bastion.graph import get_graph
        get_graph().add_node(
            "bastion:infra-map", "Asset", "infra-map",
            content={"role_map": role_map,
                     "containers": [c["name"] for c in containers]},
            meta={"kind": "infra-map", "source": "discovery"},
        )
    except Exception:
        pass
