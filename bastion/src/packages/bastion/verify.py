"""CCC 온보딩 검수 시스템 — SubAgent A2A로 인프라 상태 검증"""
from __future__ import annotations
import json
from typing import Any, Generator

# bastion의 run_command, health_check 재사용
from bastion import run_command, health_check, INTERNAL_IPS

def _ip(role: str) -> str:
    """INTERNAL_IPS에서 역할별 IP 조회 (환경변수 기반)."""
    return INTERNAL_IPS.get(role, "")


# ── 체크 정의 ─────────────────────────────────────

def _check(ip: str, name: str, script: str, expect: str, mode: str = "contains") -> dict:
    """SubAgent에 스크립트 실행 후 결과 검증.
    mode: contains(stdout에 expect 포함), not_empty(stdout 비어있지 않음), gt_zero(숫자>0)
    """
    r = run_command(ip, script, timeout=15)
    stdout = r.get("stdout", "").strip()
    stderr = r.get("stderr", "").strip()
    exit_code = r.get("exit_code", -1)

    if exit_code == -1 and "unreachable" in stderr.lower():
        return {"name": name, "passed": False, "detail": "SubAgent 접근 불가"}

    if mode == "contains":
        passed = expect.lower() in stdout.lower()
    elif mode == "not_empty":
        passed = len(stdout) > 0
    elif mode == "gt_zero":
        try:
            passed = int(stdout.split()[0]) > 0
        except (ValueError, IndexError):
            passed = False
    elif mode == "exit_zero":
        passed = exit_code == 0
    elif mode == "http_ok":
        passed = stdout in ("200", "301", "302", "403")
    else:
        passed = expect in stdout

    detail = stdout[:150] if stdout else stderr[:150]
    return {"name": name, "passed": passed, "detail": detail}


# ── 역할별 체크 ───────────────────────────────────

def _checks_common(ip: str, role: str) -> list[dict]:
    """공통 체크: SubAgent, 내부 IP, 게이트웨이"""
    checks = []
    # SubAgent
    h = health_check(ip)
    checks.append({
        "name": "subagent_running",
        "passed": h.get("status") == "healthy",
        "detail": json.dumps(h, ensure_ascii=False)[:100],
    })
    # 내부 IP
    expected_ip = INTERNAL_IPS.get(role, "")
    if expected_ip:
        checks.append(_check(ip, "internal_ip", f"ip addr show | grep {expected_ip}", expected_ip))
    # 기본 게이트웨이 (secu 자신은 제외)
    if role != "secu":
        checks.append(_check(ip, "default_gateway", "ip route show default", _ip('secu')))
    return checks


def _checks_secu(ip: str) -> list[dict]:
    return [
        _check(ip, "ip_forwarding", "sysctl -n net.ipv4.ip_forward", "1"),
        _check(ip, "nftables_rules", "nft list ruleset 2>/dev/null | wc -l", "", mode="gt_zero"),
        _check(ip, "nftables_nat", "nft list ruleset 2>/dev/null | grep masquerade", "masquerade"),
        _check(ip, "suricata_running", "systemctl is-active suricata 2>/dev/null", "active"),
        _check(ip, "suricata_rules", "ls /var/lib/suricata/rules/ 2>/dev/null | head -5", "", mode="not_empty"),
        _check(ip, "rsyslog_forward", f"grep -r '{_ip('siem')}' /etc/rsyslog.d/ 2>/dev/null", _ip('siem')),
    ]


def _checks_web(ip: str) -> list[dict]:
    return [
        _check(ip, "apache2_running", "systemctl is-active apache2 2>/dev/null", "active"),
        _check(ip, "modsecurity_module", "apachectl -M 2>/dev/null | grep security2", "security2"),
        _check(ip, "modsecurity_crs", "ls /etc/modsecurity/crs/rules/*.conf /usr/share/modsecurity-crs/rules/*.conf 2>/dev/null | wc -l", "", mode="gt_zero"),
        _check(ip, "juiceshop_running", "curl -s -o /dev/null -w '%{http_code}' http://localhost:3000 2>/dev/null", "", mode="http_ok"),
        _check(ip, "dvwa_running", "curl -s -o /dev/null -w '%{http_code}' http://localhost:8080 2>/dev/null", "", mode="http_ok"),
        _check(ip, "wazuh_agent", "systemctl is-active wazuh-agent 2>/dev/null", "active"),
        _check(ip, "rsyslog_forward", f"grep -r '{_ip('siem')}' /etc/rsyslog.d/ 2>/dev/null", _ip('siem')),
    ]


def _checks_siem(ip: str) -> list[dict]:
    return [
        _check(ip, "wazuh_manager_running", "systemctl is-active wazuh-manager 2>/dev/null", "active"),
        _check(ip, "wazuh_authd", "ss -tlnp | grep :1515", "1515"),
        _check(ip, "syslog_listener", "ss -tlnp | grep :514", "514"),
        _check(ip, "agents_enrolled", "/var/ossec/bin/agent_control -l 2>/dev/null | grep -c Active || echo 0", "", mode="gt_zero"),
        _check(ip, "ossec_logs", "ls -la /var/ossec/logs/ossec.log 2>/dev/null | head -1", "", mode="not_empty"),
    ]


def _checks_attacker(ip: str) -> list[dict]:
    return [
        _check(ip, "nmap", "which nmap", "/nmap"),
        _check(ip, "sqlmap", "which sqlmap", "/sqlmap"),
        _check(ip, "hydra", "which hydra", "/hydra"),
        _check(ip, "wazuh_agent", "systemctl is-active wazuh-agent 2>/dev/null", "active"),
    ]


def _checks_manager(ip: str) -> list[dict]:
    return [
        _check(ip, "python3", "python3 --version", "Python"),
        _check(ip, "ccc_repo", "ls /opt/ccc/apps/ccc_api/src/main.py 2>/dev/null", "main.py"),
    ]


def _checks_windows(ip: str) -> list[dict]:
    """Windows 검수 — SubAgent health만 확인"""
    h = health_check(ip)
    return [{
        "name": "subagent_running",
        "passed": h.get("status") == "healthy",
        "detail": json.dumps(h, ensure_ascii=False)[:100],
    }]


ROLE_CHECKS = {
    "secu": _checks_secu,
    "siem": _checks_siem,
    "web": _checks_web,
    "attacker": _checks_attacker,
    "manager": _checks_manager,
    "windows": _checks_windows,
}


# ── 네트워크 흐름 E2E 테스트 ──────────────────────

def _checks_network_flow(ips: dict[str, str]) -> list[dict]:
    """attacker → web 경유 트래픽 흐름 검증
    nftables → suricata → modsecurity → webserver
    """
    checks = []
    attacker_ip = ips.get("attacker", "")
    secu_ip = ips.get("secu", "")
    web_ip = ips.get("web", "")

    if not all([attacker_ip, secu_ip, web_ip]):
        return [{"name": "network_flow", "passed": False, "detail": "attacker/secu/web IP 필요"}]

    # 1. attacker에서 web으로 정상 HTTP 요청
    checks.append(_check(attacker_ip, "http_to_web",
                         f"curl -s -o /dev/null -w '%{{http_code}}' http://{_ip('web')}/ 2>/dev/null || echo 000",
                         "", mode="http_ok"))

    # 2. attacker에서 web으로 SQL Injection 시도 (modsecurity 탐지 대상)
    r = run_command(attacker_ip,
                    f"curl -s -o /dev/null -w '%{{http_code}}' 'http://{_ip('web')}/?id=1%20OR%201=1' 2>/dev/null || echo 000",
                    timeout=10)
    sqli_code = r.get("stdout", "").strip()
    # modsecurity가 차단하면 403, 아니면 200
    checks.append({
        "name": "modsecurity_sqli_block",
        "passed": sqli_code == "403",
        "detail": f"HTTP {sqli_code} (403이면 차단 성공)",
    })

    # 3. secu에서 suricata 로그 확인 (최근 eve.json에 alert 존재)
    import time
    time.sleep(2)  # 로그 기록 대기
    checks.append(_check(secu_ip, "suricata_eve_log",
                         "test -f /var/log/suricata/eve.json && tail -20 /var/log/suricata/eve.json | grep -c 'event_type' || echo 0",
                         "", mode="gt_zero"))

    # 4. web에서 modsecurity 차단 로그 확인 (error.log 또는 audit log)
    checks.append(_check(web_ip, "modsecurity_block_log",
                         "grep -c 'ModSecurity: Access denied' /var/log/apache2/error.log 2>/dev/null || "
                         "grep -c 'ModSecurity' /var/log/apache2/modsec_audit.log 2>/dev/null || echo 0",
                         "", mode="gt_zero"))

    return checks


# ── 검수 오케스트레이터 ───────────────────────────

def verify_role(role: str, ip: str, all_ips: dict[str, str] | None = None) -> Generator[dict, None, None]:
    """단일 역할 검수 — SSE 이벤트 generator"""
    yield {"event": "verify_start", "role": role, "ip": ip}

    # 공통 체크
    common = _checks_common(ip, role)
    for c in common:
        c["category"] = "common"
        yield {"event": "verify_check", "role": role, **c}

    # 역할별 체크
    role_fn = ROLE_CHECKS.get(role)
    if role_fn:
        role_checks = role_fn(ip)
        for c in role_checks:
            c["category"] = role
            yield {"event": "verify_check", "role": role, **c}
    else:
        role_checks = []

    all_checks = common + role_checks
    passed = sum(1 for c in all_checks if c.get("passed"))
    total = len(all_checks)
    yield {
        "event": "verify_done", "role": role,
        "passed": passed == total,
        "summary": f"{passed}/{total}",
    }


def verify_all_stream(infra_ips: dict[str, str], include_windows: bool = False) -> Generator[dict, None, None]:
    """전체 인프라 검수 — SSE 이벤트 generator"""
    roles = ["secu", "siem", "web", "attacker", "manager"]
    if include_windows and "windows" in infra_ips:
        roles.append("windows")

    total_passed = 0
    total_checks = 0

    for role in roles:
        ip = infra_ips.get(role)
        if not ip:
            yield {"event": "verify_done", "role": role, "passed": False, "summary": "IP 없음"}
            continue

        role_passed = 0
        role_total = 0
        for evt in verify_role(role, ip, infra_ips):
            if evt["event"] == "verify_check":
                role_total += 1
                if evt.get("passed"):
                    role_passed += 1
            yield evt

        total_passed += role_passed
        total_checks += role_total

    # 네트워크 흐름 E2E
    yield {"event": "verify_start", "role": "network_flow", "ip": ""}
    flow_checks = _checks_network_flow(infra_ips)
    for c in flow_checks:
        c["category"] = "network_flow"
        total_checks += 1
        if c.get("passed"):
            total_passed += 1
        yield {"event": "verify_check", "role": "network_flow", **c}

    flow_passed = sum(1 for c in flow_checks if c.get("passed"))
    yield {
        "event": "verify_done", "role": "network_flow",
        "passed": flow_passed == len(flow_checks),
        "summary": f"{flow_passed}/{len(flow_checks)}",
    }

    yield {
        "event": "verify_complete",
        "total_checks": total_checks,
        "total_passed": total_passed,
        "all_passed": total_passed == total_checks,
    }
