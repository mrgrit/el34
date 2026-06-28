"""Bastion Target Resolver — 서비스 역할(role) → 실행 대상(컨테이너/호스트) 해석.

목적(Phase B): bastion 을 **범용**으로 — 특정 배포(el34)의 컨테이너 이름을 코드에
하드코딩하지 않고, 부팅 시 발견(discovery)한 인프라에 맞춰 동작하게 한다.

핵심 개념
---------
- bastion 은 자기 컨테이너의 docker.sock 으로 다른 컨테이너에 `docker exec` 한다
  (대부분의 보안 점검 스킬이 이 경로). 즉 "대상"은 기계가 아니라 **자산(컨테이너)** 이다.
- 스킬은 서비스 **역할**(ids/siem/web/fw/attacker …)로 대상을 가리키고, 이 모듈이
  역할 → 실제 컨테이너 이름으로 해석한다.

해석 우선순위
-------------
1. discovery 활성(`BASTION_DISCOVERY=1`) + 발견된 매핑 있음 → 발견된 컨테이너.
2. 그 외 → **STATIC_CONTAINERS 정적 폴백(현 el34 이름)** → *기존 동작과 100% 동일*.
   (discovery 미실행/매칭 실패 시에도 el34 가 그대로 동작하도록 보장하는 안전망.)

이 설계로 el34 는 무회귀(no regression), 다른 인프라는 discovery 로 자동 적응한다.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


# ── 정적 폴백 맵 (현 el34 컨테이너 이름) ────────────────────────────────────
# discovery 가 없거나 해당 역할을 확신 못할 때 이 값을 쓴다 → 기존 el34 동작 보존.
# 키 = 서비스 역할(스킬이 부르는 이름) · 값 = 컨테이너 이름.
STATIC_CONTAINERS: dict[str, str] = {
    "attacker": "el34-attacker",
    "ids": "el34-ips", "ips": "el34-ips", "suricata": "el34-ips",
    "siem": "el34-siem", "wazuh": "el34-siem", "manager_siem": "el34-siem",
    "web": "el34-web", "waf": "el34-web", "modsec": "el34-web", "apache": "el34-web",
    "fw": "el34-fw", "firewall": "el34-fw", "nftables": "el34-fw", "secu": "el34-fw",
    "bastion": "el34-bastion", "portal": "el34-portal",
}


@dataclass
class ExecTarget:
    """역할 해석 결과. wrap() 으로 (run_command 용 ip, script) 를 만든다."""
    role: str
    container: str                 # 실행 대상 컨테이너 이름(발견 또는 폴백)
    exec_mode: str = "docker_exec" # docker_exec | ssh_subagent | local
    bastion_ip: str = "127.0.0.1"  # docker.sock 보유 호스트(docker_exec 시)
    ip: str = ""                   # ssh_subagent 시 직접 대상 IP

    def wrap(self, inner_cmd: str) -> tuple[str, str]:
        """inner_cmd 를 실행 모드에 맞춰 (run_command ip, script) 로 변환."""
        if self.exec_mode == "local":
            return ("127.0.0.1", inner_cmd)
        if self.exec_mode == "ssh_subagent" and self.ip:
            return (self.ip, inner_cmd)
        # docker_exec (기본): bastion 의 docker.sock 으로 컨테이너 내부 실행
        esc = inner_cmd.replace('"', '\\"')
        return (self.bastion_ip, f'docker exec {self.container} sh -c "{esc}"')


def _discovered_container(role: str) -> str | None:
    """discovery 활성 시 발견된 역할→컨테이너 매핑 조회(없으면 None)."""
    if os.getenv("BASTION_DISCOVERY", "0") != "1":
        return None
    try:
        from bastion.discovery import get_discovered_container
        return get_discovered_container(role)
    except Exception:
        return None


def container_for(role: str) -> str:
    """서비스 역할 → 컨테이너 이름. discovery 우선, 없으면 정적 el34 폴백.

    스킬 코드에서 `docker exec el34-ips` 대신 `docker exec {container_for('ids')}` 로 쓴다.
    """
    return (_discovered_container(role)
            or STATIC_CONTAINERS.get(role)
            or (f"el34-{role}" if role and not role[0].isdigit() else role))


def resolve_target(role: str, vm_ips: dict[str, str] | None = None) -> ExecTarget:
    """역할 → ExecTarget. docker_exec 기본(bastion docker.sock).

    discovery 가 ssh_subagent 모드를 지정하면 그 IP 로 직접 실행하도록 확장 가능.
    """
    vm_ips = vm_ips or {}
    bastion_ip = vm_ips.get("bastion") or "127.0.0.1"
    container = container_for(role)
    return ExecTarget(role=role, container=container,
                      exec_mode="docker_exec", bastion_ip=bastion_ip)
