"""bastion — CCC 운영 관리 에이전트

Claude Code 아키텍처를 참고한 CCC 인프라/운영 관리 시스템.
시스템 프롬프트 동적 조합 + SubAgent 제어 + SSH 온보딩 + 헬스체크.

핵심 기능:
1. 인프라 온보딩 (SSH → SubAgent 설치)
2. 헬스체크 (SubAgent 상태 확인)
3. SubAgent 명령 실행 (A2A 프로토콜)
4. LLM 기반 작업 디스패치 (스킬 시스템)
5. 시스템 상태 모니터링
"""
from __future__ import annotations
import os
import json
import subprocess
from typing import Any

import httpx

# ── Config ────────────────────────────────────────
def _require_env(key: str) -> str:
    val = os.getenv(key)
    if not val:
        raise ValueError(f"{key} is not set — add it to .env")
    return val

LLM_BASE_URL       = _require_env("LLM_BASE_URL")
LLM_MANAGER_MODEL  = _require_env("LLM_MANAGER_MODEL")
LLM_SUBAGENT_MODEL = _require_env("LLM_SUBAGENT_MODEL")
# bastion TUI는 manager 모델 사용
LLM_MODEL = LLM_MANAGER_MODEL
SUBAGENT_PORT = 8002
SSH_TIMEOUT = 120  # 온보딩 시 패키지 설치에 시간 필요

# ── System Prompt Sections (bastion/src/constants 참고) ──

CCC_DIR = os.getenv("CCC_DIR", os.path.join(os.path.dirname(__file__), "..", ".."))

PROMPT_SECTIONS = {
    "identity": """너는 CCC(Cyber Combat Commander)의 Bastion 운영 에이전트다.
CCC 교육 플랫폼의 **모든 운영 업무**를 담당한다.
서버 관리, 서비스 시작/중지, 인프라 관리, 모니터링, 문제 해결 등 관리자가 요청하는 모든 작업을 수행한다.""",

    "architecture": """CCC 아키텍처:
- ccc-api (:9100): FastAPI 메인 서버. ./dev.sh api 로 실행. UI도 /app/ 경로로 서빙.
- ccc-ui: React 웹 UI. npm run build로 빌드 → ccc-api가 정적 파일 서빙.
- bastion: 이 에이전트. ./dev.sh bastion 으로 실행.
- PostgreSQL (:5434): docker compose -f docker/docker-compose.yaml up -d postgres
- Ollama (LLM): 외부 또는 로컬 서버. 환경변수 LLM_BASE_URL로 설정.

핵심 파일:
- ./dev.sh: API/bastion 실행 스크립트
- .env: 환경 설정 (DATABASE_URL, LLM_BASE_URL, LLM_MODEL)
- docker/docker-compose.yaml: PostgreSQL + API 컨테이너
- apps/ccc_api/src/main.py: API 소스
- apps/ccc-ui/: React UI 소스""",

    "capabilities": """사용 가능한 스킬:
- shell: 이 서버에서 로컬 명령 실행 (서비스 시작/중지, 파일 확인, 로그 조회 등)
- service: CCC 서비스 관리 (api 시작/중지/재시작, db 시작/중지, 상태 확인)
- onboard: 학생 VM에 SSH 접속 → SubAgent 설치 + 역할별 소프트웨어 배포
- health_check: SubAgent 상태 확인 (A2A /health)
- run_command: SubAgent에 원격 명령 실행 (A2A /a2a/run_script)
- system_status: 전체 인프라 상태 요약
- diagnose: VM 문제 진단 (상태 수집 + LLM 분석)
- build_ui: UI 빌드 (npm run build)""",

    "constraints": """제약사항:
- 파괴적 작업(rm -rf /, 디스크 포맷) 금지
- 학생 데이터 임의 삭제 금지
- DB DROP TABLE 금지""",

    "reasoning": """결과 해석 + 자기수정 가이드:

1. exit_code 해석 — 0 만 성공이 아님:
   - `which foo bar baz` 처럼 *복수 인자 명령* 은 1 개라도 missing 시 exit_code 1.
     stdout 에 *발견된 항목 PATH* 가 있으므로 partial pass — 발견된 항목을 보고하고
     missing 항목은 명시. 같은 명령 반복 X.
   - `grep` 의 exit_code 1 = 매치 없음 (정상 동작, 실패 아님).
   - `find` 의 empty stdout = 그 path 에 없음 (정상). 다른 path 추가 검색은 의미 있을 때만.
   - 단일 명령 (예: `ls /tmp`) 의 exit_code 1+ = 진짜 실패. retry.

2. multi-intent 분해 — 한 task 가 N 의도면 N step 으로 분해:
   - 예: "13 도구 매트릭스 + 버전 + ATT&CK 매핑" = 3 step.
   - 한 shell 명령에 모두 묶으려 하지 말 것. step 별로 stdout 명확.
   - step 1 의 stdout 을 step 2 의 input 으로 (자기 reference).

3. partial result 처리 — stdout 에 *부분 결과* 있으면:
   - 부분 결과를 응답에 명시 ("X/Y 항목 발견")
   - 누락 항목의 *원인 추정* ("install 안 됐을 가능성") + 검증 명령 1 회
   - 같은 명령 반복 또는 무의미 fallback (chmod 750 등) 금지.

4. 자기수정 종료 조건:
   - 3 회 retry 후 동일 fail → planning 으로 복귀, 다른 접근 시도.
   - 같은 명령 (또는 변수 비어 무의미 명령) 5 회 이상 반복 시 즉시 중단 + 사람 보고.""",

    "roles": """학생 VM 역할:
- attacker (Kali): nmap, metasploit, hydra, sqlmap, nikto, gobuster
- secu (Security GW): nftables, suricata, sysmon, osquery, auditd (NIC 2개)
- web (Web Server): apache2, modsecurity, docker(juiceshop/dvwa)
- siem (SIEM): wazuh-manager, sigma, opencti, elasticsearch (RAM 8G+)
- windows (분석): sysmon, osquery, ghidra (OpenSSH 필요)
- manager (Manager AI): ollama, ccc-bastion subagent""",
}


def _load_ccc_md() -> str:
    """CCC.md 로드 — bastion의 장기 기억/운영 지침"""
    ccc_md = os.path.join(CCC_DIR, "CCC.md")
    if os.path.exists(ccc_md):
        try:
            with open(ccc_md, encoding="utf-8") as f:
                return f.read()[:3000]
        except Exception:
            pass
    return ""

def build_system_prompt(extra_context: str = "") -> str:
    """시스템 프롬프트 동적 조합 (bastion의 resolveSystemPromptSections 참고)"""
    sections = [PROMPT_SECTIONS[k] for k in PROMPT_SECTIONS]
    # CCC.md 장기 기억 주입
    ccc_md = _load_ccc_md()
    if ccc_md:
        sections.append(f"[CCC 운영 지침]\n{ccc_md}")
    if extra_context:
        sections.append(f"현재 상황:\n{extra_context}")
    return "\n\n".join(sections)


# ── SSH Onboarding ────────────────────────────────

# 역할별 설치 스크립트
# ── Wazuh Agent 설치 (web, attacker에서 공통 사용) ──
# - 버전: Wazuh Manager와 일치시키기 위해 4.10.3-1 고정 (더 높으면 manager가 거부)
# - dpkg lock: unattended-upgrades 경쟁 방지를 위해 최대 90s 대기
# - SIEM 준비: 10.20.30.100:1515 (authd) 포트 열림까지 최대 60s 대기
# - agent-auth 실패 시에도 서비스는 시작 (첫 등록은 agent 내장 enrollment로 재시도됨)
WAZUH_AGENT_INSTALL = """
# dpkg lock 대기 (최대 90초)
for i in $(seq 1 30); do
  fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break
  sleep 3
done
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import 2>/dev/null && chmod 644 /usr/share/keyrings/wazuh.gpg
echo 'deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main' > /etc/apt/sources.list.d/wazuh.list
apt-get update -y
# 버전 고정 (Manager 4.10.3과 일치). 실패 시 최신 fallback (후속 diagnose가 잡음)
WAZUH_MANAGER="10.20.30.100" DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-downgrades wazuh-agent=4.10.3-1 2>&1 | tail -3 || \\
  WAZUH_MANAGER="10.20.30.100" DEBIAN_FRONTEND=noninteractive apt-get install -y wazuh-agent 2>&1 | tail -3
if [ -f /var/ossec/bin/agent-auth ]; then
    sed -i 's|<address>.*</address>|<address>10.20.30.100</address>|g' /var/ossec/etc/ossec.conf 2>/dev/null || true
    # SIEM manager 준비 대기 (최대 60초)
    for i in $(seq 1 20); do
      (echo > /dev/tcp/10.20.30.100/1515) 2>/dev/null && break
      sleep 3
    done
    /var/ossec/bin/agent-auth -m 10.20.30.100 2>&1 | tail -3 || true
    systemctl daemon-reload
    systemctl enable --now wazuh-agent 2>&1 | tail -2
fi
"""

# 역할별 설치 스크립트 — 기본 온보딩 (서비스 설치 + 시작 + 기본 설정)
# 강좌/주차별 세부 설정은 Lab 실행 시 추가 적용
ROLE_SETUP_SCRIPTS: dict[str, list[str]] = {
    "attacker": [
        "apt-get update -y",
        "apt-get install -y nmap hydra sqlmap nikto dirb gobuster seclists curl net-tools traceroute whatweb enum4linux hashcat john python3-impacket smbclient",
        # metasploit framework
        "if ! command -v msfconsole &>/dev/null; then curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall && chmod 755 /tmp/msfinstall && /tmp/msfinstall; fi",
        WAZUH_AGENT_INSTALL,
    ],
    "secu": [
        # ── 패키지 설치 ──
        "apt-get update -y",
        "apt-get install -y nftables suricata auditd rsyslog libpam-pwquality",
        # ── IP 포워딩 ──
        "sysctl -w net.ipv4.ip_forward=1",
        "grep -q 'net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf",
        # ── Suricata 기본 설정 + 룰 업데이트 ──
        """
suricata-update 2>/dev/null || true
# HOME_NET 설정
if [ -f /etc/suricata/suricata.yaml ]; then
    sed -i 's|HOME_NET:.*|HOME_NET: "[10.20.30.0/24]"|' /etc/suricata/suricata.yaml
    # af-packet 인터페이스 자동 감지 (내부 NIC)
    IFACE=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{print $2}' | tr -d ':' | tail -1)
    if [ -n "$IFACE" ]; then
        sed -i "s|interface: eth0|interface: $IFACE|g" /etc/suricata/suricata.yaml 2>/dev/null || true
    fi
fi
systemctl enable --now suricata 2>/dev/null || true
""",
        # ── nftables 기본 방화벽 + NAT ──
        # 외부(EXTERNAL) / 내부(INTERNAL) NIC 자동 감지.
        # head -1 = 첫 NIC = 외부망(예: ens33), tail -1 = 마지막 NIC = 내부망(예: ens34).
        # 실패 시 hard-fail 로 잘못된 빈 EXTERNAL/INTERNAL 로 룰 만들지 않음.
        """
EXTERNAL=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{print $2}' | tr -d ':' | head -1)
INTERNAL=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{print $2}' | tr -d ':' | tail -1)
if [ -z "$EXTERNAL" ] || [ -z "$INTERNAL" ] || [ "$EXTERNAL" = "$INTERNAL" ]; then
    echo "[ERROR] NIC 감지 실패: EXTERNAL='$EXTERNAL' INTERNAL='$INTERNAL'. ip link 확인 필요." >&2
    exit 1
fi
echo "[NFT] EXTERNAL=$EXTERNAL INTERNAL=$INTERNAL"
cat > /etc/nftables.conf << NFTEOF
#!/usr/sbin/nft -f
flush ruleset
table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        ip saddr 10.20.30.0/24 accept
        tcp dport 22 accept
        tcp dport 8002 accept
        icmp type echo-request accept
        ip6 nexthdr icmpv6 accept
    }
    chain forward {
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
        iifname "$EXTERNAL" tcp dport 80 dnat to 10.20.30.80:80
        iifname "$EXTERNAL" tcp dport 443 dnat to 10.20.30.80:443
        iifname "$EXTERNAL" tcp dport 3000 dnat to 10.20.30.80:3000
        iifname "$EXTERNAL" tcp dport 8080 dnat to 10.20.30.80:8080
    }
    chain postrouting {
        type nat hook postrouting priority 100;
        # 1) 내부 VM 의 외부 인터넷 접근 (기존)
        oifname "$EXTERNAL" masquerade
        # 2) DNAT 트래픽 SNAT — 외부 클라이언트의 응답 경로 보장 (asymmetric routing 회피).
        #    backend 가 secu 가 아닌 기본 게이트웨이로 응답 라우팅하더라도 secu IP 로 source 가 바뀌어 정상 작동.
        ip saddr != 10.20.30.0/24 oifname "$INTERNAL" ip daddr 10.20.30.0/24 masquerade
    }
}
NFTEOF
nft -f /etc/nftables.conf || { echo "[ERROR] nft -f 실패" >&2; exit 1; }
systemctl enable --now nftables
# 검증 — DNAT 룰이 실제로 로드됐는지 확인
echo "[NFT] 적용 후 nat 룰:"
nft list table ip nat 2>&1 | head -30
# net.ipv4.ip_forward 재확인
test "$(cat /proc/sys/net/ipv4/ip_forward)" = "1" || sysctl -w net.ipv4.ip_forward=1
""",
        # ── rsyslog → SIEM 포워딩 ──
        """
cat > /etc/rsyslog.d/50-ccc-siem.conf << 'RSEOF'
*.* @@10.20.30.100:514
RSEOF
systemctl restart rsyslog
""",
        # ── dnsmasq 내부 DNS ──
        """
apt-get install -y dnsmasq
# systemd-resolved stub 비활성화 (포트 53 충돌 방지)
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/no-stub.conf << 'RESEOF'
[Resolve]
DNSStubListener=no
RESEOF
systemctl restart systemd-resolved 2>/dev/null || true
# dnsmasq 설정
cat > /etc/dnsmasq.d/ccc.conf << 'DNSEOF'
domain-needed
bogus-priv
no-resolv
bind-dynamic
listen-address=127.0.0.1,10.20.30.1
server=8.8.8.8
server=1.1.1.1
address=/attacker/10.20.30.201
address=/web/10.20.30.80
address=/siem/10.20.30.100
address=/manager/10.20.30.200
address=/secu/10.20.30.1
address=/windows/10.20.30.50
DNSEOF
systemctl enable --now dnsmasq
""",
    ],
    "web": [
        # ── 패키지 설치 ──
        "apt-get update -y",
        "apt-get install -y apache2 docker.io libapache2-mod-security2 curl",
        # ── ModSecurity 기본 활성화 ──
        """
if [ -f /etc/modsecurity/modsecurity.conf-recommended ] && [ ! -f /etc/modsecurity/modsecurity.conf ]; then
    cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
fi
if [ -f /etc/modsecurity/modsecurity.conf ]; then
    sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf
fi
# OWASP CRS 설치 + 최소 설정
apt-get install -y modsecurity-crs 2>/dev/null || true
a2disconf modsecurity-crs 2>/dev/null || true
# CRS 초기화 설정 (없으면 REQUEST-901이 500 에러 발생)
cat > /etc/modsecurity/crs/crs-setup.conf << 'CRSEOF'
SecAction "id:900000,phase:1,nolog,pass,t:none,setvar:tx.crs_setup_version=330"
SecAction "id:900001,phase:1,nolog,pass,t:none,setvar:tx.paranoia_level=1"
SecAction "id:900100,phase:1,nolog,pass,t:none,setvar:tx.enforce_bodyproc_urlencoded=1"
SecAction "id:900110,phase:1,nolog,pass,t:none,setvar:tx.inbound_anomaly_score_threshold=5,setvar:tx.outbound_anomaly_score_threshold=4"
SecAction "id:900300,phase:1,nolog,pass,t:none,setvar:tx.max_num_args=255"
SecAction "id:900400,phase:1,nolog,pass,t:none,setvar:tx.max_file_size=1048576"
CRSEOF
a2enmod security2 proxy proxy_http headers 2>/dev/null || true
systemctl restart apache2
""",
        # ── Docker 서비스 + 웹 앱 컨테이너 (JuiceShop + DVWA + 5 vuln-sites) ──
        # docker-compose 설치 (vuln-sites 배포용 — Ubuntu apt 의 docker.io 는 plugin 없음)
        "apt-get install -y docker-compose 2>/dev/null || true",
        # Docker daemon DNS 설정 — 컨테이너가 secu(10.20.30.1, DNS 미운영) 가 아닌 8.8.8.8 사용
        # (이전 버그: vuln-sites docker build 시 pypi.org 해상 실패)
        """
mkdir -p /etc/docker
if [ ! -f /etc/docker/daemon.json ] || ! grep -q '"dns"' /etc/docker/daemon.json; then
    cat > /etc/docker/daemon.json << 'DOCKEREOF'
{
  "dns": ["8.8.8.8", "1.1.1.1"]
}
DOCKEREOF
    systemctl restart docker
fi
""",
        """
systemctl enable --now docker
docker rm -f juiceshop dvwa 2>/dev/null || true
docker run -d --restart=always --name juiceshop -p 3000:3000 bkimminich/juice-shop 2>/dev/null || true
docker run -d --restart=always --name dvwa -p 8080:80 vulnerables/web-dvwa 2>/dev/null || true
""",
        # ── 5 vuln-sites 자동 배포 (NeoBank/GovPortal/MediForum/AdminConsole/AICompanion) ──
        # 소스코드는 manager(bastion) 가 SubAgent 로 /opt/vuln-sites/ 에 사전 동기화 가정.
        # 미동기화 시 skip — 학생 재온보딩 시 ccc-api 가 별도 deploy 단계로 처리 가능.
        """
if [ -d /opt/vuln-sites ] && command -v docker-compose >/dev/null 2>&1; then
    docker network create ccc-vuln 2>/dev/null || true
    for s in neobank govportal mediforum adminconsole aicompanion; do
        if [ -d /opt/vuln-sites/$s ]; then
            ( cd /opt/vuln-sites/$s && docker-compose up -d --build 2>&1 | tail -2 ) &
        fi
    done
    wait
    echo "vuln-sites 5종 deploy attempted (bg builds)"
else
    echo "vuln-sites skip: /opt/vuln-sites 미존재 또는 docker-compose 미설치"
fi
""",
        # ── 외부 NIC 직접 접근 차단 (secu 외부 IP 통한 DNAT 만 허용) ──
        # NAT 정책: 학생/관리자/공격자 모든 트래픽이 secu 의 외부 IP 로만 들어와야 함
        # web 의 외부 IP (192.168.0.x) 직접 접근은 차단 → port 식별성 + 일관 정책
        """
# 1. inet filter input — kernel-level (non-Docker) 트래픽
nft add table inet filter 2>/dev/null || true
nft 'add chain inet filter input { type filter hook input priority filter; policy accept; }' 2>/dev/null || true
add_input_rule() {
    local rule="$1"
    if ! nft list ruleset 2>/dev/null | grep -qF "$rule"; then
        nft add rule inet filter input $rule
    fi
}
add_input_rule 'iif lo accept'
add_input_rule 'ct state established,related accept'
add_input_rule 'iifname ens37 accept'
add_input_rule 'iifname ens33 tcp dport 22 accept'
add_input_rule 'iifname ens33 tcp dport 8002 accept'
add_input_rule 'iifname ens33 icmp type echo-request accept'
add_input_rule 'iifname ens33 tcp dport { 80, 3000, 3001, 3002, 3003, 3004, 3005, 8080 } drop'

# 2. iptables DOCKER-USER chain — Docker published port 우회 차단
# DOCKER-USER 가 DOCKER chain 보다 먼저 평가됨
iptables -F DOCKER-USER 2>/dev/null || true
iptables -A DOCKER-USER -i ens33 -s 10.20.30.0/24 -j ACCEPT
iptables -A DOCKER-USER -i ens33 -s 192.168.0.0/24 -p tcp --dport 8002 -j ACCEPT  # SubAgent (관리망 직접)
for p in 80 3000 3001 3002 3003 3004 3005 8080; do
    iptables -A DOCKER-USER -i ens33 -p tcp --dport $p -j DROP
done
iptables -A DOCKER-USER -j RETURN

# 3. 영구화
nft list ruleset > /etc/nftables.conf
mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4
systemctl enable nftables 2>/dev/null || true
echo "external direct access blocked — only via secu DNAT"
""",
        # ── Apache → JuiceShop 리버스 프록시 (포트 80) ──
        """
cat > /etc/apache2/sites-available/juiceshop.conf << 'APEOF'
<VirtualHost *:80>
    ProxyPreserveHost On
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/
    Header always set X-Forwarded-Proto http
</VirtualHost>
APEOF
a2dissite 000-default 2>/dev/null || true
a2ensite juiceshop
systemctl reload apache2
""",
        # ── rsyslog → SIEM ──
        """
cat > /etc/rsyslog.d/50-ccc-siem.conf << 'RSEOF'
*.* @@10.20.30.100:514
RSEOF
systemctl restart rsyslog
""",
        # ── Wazuh Agent ──
        WAZUH_AGENT_INSTALL,
    ],
    "siem": [
        # ── Wazuh All-in-One 공식 설치 (Manager + Indexer + Dashboard + Filebeat) ──
        "apt-get update -y && apt-get install -y curl apt-transport-https gnupg2",
        # 공식 설치 스크립트 다운로드
        """
cd /tmp
curl -sO https://packages.wazuh.com/4.10/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.10/config.yml
# config.yml 단일 노드 설정
cat > /tmp/config.yml << 'CFGEOF'
nodes:
  indexer:
    - name: node-1
      ip: 127.0.0.1
  server:
    - name: wazuh-1
      ip: 127.0.0.1
  dashboard:
    - name: dashboard
      ip: 127.0.0.1
CFGEOF
chmod +x /tmp/wazuh-install.sh
""",
        # All-in-One 설치 실행 (--ignore-check: 리소스 체크 무시)
        "cd /tmp && bash wazuh-install.sh -a --ignore-check 2>&1 | tail -20",
        # ── 설치 후 추가 설정: syslog + agent 등록 ──
        """
if [ -f /var/ossec/etc/ossec.conf ]; then
    # syslog 리스너 활성화 (514/tcp)
    if ! grep -q '<connection>syslog</connection>' /var/ossec/etc/ossec.conf; then
        sed -i '/<\\/ossec_config>/i \\
  <remote>\\n    <connection>syslog</connection>\\n    <port>514</port>\\n    <protocol>tcp</protocol>\\n    <allowed-ips>10.20.30.0/24</allowed-ips>\\n  </remote>' /var/ossec/etc/ossec.conf
    fi
    # 에이전트 자동 등록
    if ! grep -q '<auth>' /var/ossec/etc/ossec.conf; then
        sed -i '/<\\/ossec_config>/i \\
  <auth>\\n    <disabled>no</disabled>\\n    <port>1515</port>\\n    <use_password>yes</use_password>\\n  </auth>' /var/ossec/etc/ossec.conf
    fi
    echo 'ccc2026' > /var/ossec/etc/authd.pass 2>/dev/null || true
    systemctl restart wazuh-manager 2>/dev/null || true
fi
""",
        # ── rsyslog 수신 설정 ──
        """
cat > /etc/rsyslog.d/50-ccc-receive.conf << 'RSEOF'
module(load="imtcp")
input(type="imtcp" port="514")
RSEOF
systemctl restart rsyslog 2>/dev/null || true
""",
        # ── OpenCTI 설치 (Docker) ──
        """
# Docker 설치
if ! command -v docker &>/dev/null; then
    curl -fsSL https://get.docker.com | sh
    usermod -aG docker ccc 2>/dev/null || true
fi
systemctl enable --now docker

# OpenCTI docker-compose
mkdir -p /opt/opencti
cat > /opt/opencti/docker-compose.yml << 'OCEOF'
version: '3'
services:
  redis:
    image: redis:7
    restart: always
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    restart: always
    ulimits:
      memlock:
        soft: -1
        hard: -1
  minio:
    image: minio/minio
    environment:
      MINIO_ROOT_USER: opencti
      MINIO_ROOT_PASSWORD: opencti2026
    command: server /data --console-address ":9001"
    restart: always
  rabbitmq:
    image: rabbitmq:3-management
    environment:
      RABBITMQ_DEFAULT_USER: opencti
      RABBITMQ_DEFAULT_PASS: opencti2026
    restart: always
  opencti:
    image: opencti/platform:6.4.4
    depends_on:
      - redis
      - elasticsearch
      - minio
      - rabbitmq
    ports:
      - "8080:8080"
    environment:
      - NODE_OPTIONS=--max-old-space-size=2048
      - APP__PORT=8080
      - APP__BASE_URL=http://localhost:8080
      - APP__ADMIN__EMAIL=admin@opencti.io
      - APP__ADMIN__PASSWORD=CCC2026!
      - APP__ADMIN__TOKEN=a8f3b0c2-9d1e-4f56-8a2b-7c4d3e1f9b8a
      - REDIS__HOSTNAME=redis
      - ELASTICSEARCH__URL=http://elasticsearch:9200
      - MINIO__ENDPOINT=minio
      - MINIO__PORT=9000
      - MINIO__USE_SSL=false
      - MINIO__ACCESS_KEY=opencti
      - MINIO__SECRET_KEY=opencti2026
      - RABBITMQ__HOSTNAME=rabbitmq
      - RABBITMQ__PORT=5672
      - RABBITMQ__USERNAME=opencti
      - RABBITMQ__PASSWORD=opencti2026
      - SMTP__HOSTNAME=localhost
      - SMTP__PORT=25
    restart: always
  worker:
    image: opencti/worker:6.4.4
    depends_on:
      - opencti
    environment:
      - OPENCTI_URL=http://opencti:8080
      - OPENCTI_TOKEN=a8f3b0c2-9d1e-4f56-8a2b-7c4d3e1f9b8a
    restart: always
OCEOF

# vm.max_map_count (Elasticsearch 요구)
sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf 2>/dev/null || true

# OpenCTI 시작 (백그라운드, 이미지 pull 오래 걸림)
cd /opt/opencti && docker compose up -d 2>&1 | tail -10
echo 'OpenCTI 시작됨 — http://SIEM_IP:8080 (admin@opencti.io / CCC2026!)'
""",
        # ── 외부 NIC 직접 접근 차단 (secu 외부 IP 통한 DNAT 만 허용) ──
        # siem 의 :443 (Wazuh Dashboard), :8080 (OpenCTI), :1514/:1515/:55000 (Wazuh agent/API)
        # 모두 docker published port → DOCKER-USER chain 으로 차단
        """
# 1. inet filter input
nft add table inet filter 2>/dev/null || true
nft 'add chain inet filter input { type filter hook input priority filter; policy accept; }' 2>/dev/null || true
add_input_rule() {
    local rule="$1"
    if ! nft list ruleset 2>/dev/null | grep -qF "$rule"; then
        nft add rule inet filter input $rule
    fi
}
add_input_rule 'iif lo accept'
add_input_rule 'ct state established,related accept'
# Docker bridges trusted (siem 내부 docker network)
for iface in $(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(br-|docker)'); do
    add_input_rule "iifname $iface accept"
done
add_input_rule 'iifname ens33 tcp dport 22 accept'
add_input_rule 'iifname ens33 tcp dport 8002 accept'
add_input_rule 'iifname ens33 icmp type echo-request accept'
add_input_rule 'iifname ens33 ip saddr 10.20.30.0/24 accept'

# 2. iptables DOCKER-USER — Docker forwarded port 차단
iptables -F DOCKER-USER 2>/dev/null || true
iptables -A DOCKER-USER -i ens33 -s 10.20.30.0/24 -j ACCEPT
iptables -A DOCKER-USER -i ens33 -s 192.168.0.0/24 -p tcp --dport 8002 -j ACCEPT  # SubAgent
for p in 443 1514 1515 8080 55000; do
    iptables -A DOCKER-USER -i ens33 -p tcp --dport $p -j DROP
done
iptables -A DOCKER-USER -j RETURN

# 3. 영구화
nft list ruleset > /etc/nftables.conf
mkdir -p /etc/iptables && iptables-save > /etc/iptables/rules.v4
systemctl enable nftables 2>/dev/null || true
echo "siem external direct access blocked"
""",
    ],
    "manager": [
        # bastion 독립 설치
        "apt-get update -y && apt-get install -y python3 python3-pip python3-venv git sshpass",
        "if [ ! -d /opt/bastion ]; then git clone https://github.com/mrgrit/bastion.git /opt/bastion; else cd /opt/bastion && git pull; fi",
        "cd /opt/bastion && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt -q",
        "hostnamectl set-hostname bastion 2>/dev/null || true",
        # 사용자 접근 설정: 소유권 + 홈 심링크
        "chown -R $(logname 2>/dev/null || echo ccc):$(logname 2>/dev/null || echo ccc) /opt/bastion",
        "UHOME=$(getent passwd $(logname 2>/dev/null || echo ccc) | cut -d: -f6) && mkdir -p $UHOME && ln -sf /opt/bastion $UHOME/bastion",
    ],
}

# SubAgent 설치 스크립트 (공통)
SUBAGENT_INSTALL_SCRIPT = """#!/bin/bash
set -e
mkdir -p /opt/ccc-subagent
cat > /opt/ccc-subagent/agent.py << 'AGENT_EOF'
#!/usr/bin/env python3
\"\"\"CCC SubAgent — A2A 프로토콜 기반 경량 에이전트\"\"\"
import json, subprocess, os
from http.server import HTTPServer, BaseHTTPRequestHandler

class SubAgentHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            info = {
                "status": "healthy",
                "hostname": os.uname().nodename,
                "role": os.getenv("CCC_ROLE", "unknown"),
            }
            self.wfile.write(json.dumps(info).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/a2a/run_script":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else {}
            script = body.get("script", "echo ok")
            timeout = body.get("timeout", 60)
            try:
                r = subprocess.run(script, shell=True, capture_output=True, text=True, timeout=timeout)
                result = {"exit_code": r.returncode, "stdout": r.stdout[:10000], "stderr": r.stderr[:5000]}
            except subprocess.TimeoutExpired:
                result = {"exit_code": -1, "stdout": "", "stderr": "timeout"}
            except Exception as e:
                result = {"exit_code": -1, "stdout": "", "stderr": str(e)}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # suppress logs

if __name__ == "__main__":
    port = int(os.getenv("SUBAGENT_PORT", "8002"))
    print(f"CCC SubAgent listening on :{port}")
    HTTPServer(("0.0.0.0", port), SubAgentHandler).serve_forever()
AGENT_EOF

cat > /etc/systemd/system/ccc-subagent.service << 'SVC_EOF'
[Unit]
Description=CCC SubAgent
After=network.target
[Service]
Type=simple
Environment=CCC_ROLE={role}
ExecStart=/usr/bin/python3 /opt/ccc-subagent/agent.py
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
SVC_EOF

systemctl daemon-reload
systemctl enable --now ccc-subagent
"""


def ssh_test(ip: str, user: str, password: str) -> dict:
    """SSH 연결 + sudo 권한을 단계적으로 검증. 실패 시 원인을 분류해서 반환."""
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

    # 1단계: SSH 연결 + 인증
    try:
        r = subprocess.run(
            ["sshpass", "-p", password, "ssh", *ssh_opts, f"{user}@{ip}", "echo __ccc_ok__"],
            capture_output=True, text=True, timeout=15, errors="replace",
        )
        stdout, stderr = r.stdout, r.stderr
        if r.returncode != 0:
            if "Permission denied" in stderr:
                return {"ok": False, "stage": "auth", "error": f"SSH 인증 실패 — 계정({user}) 또는 비밀번호가 틀립니다"}
            if "Connection refused" in stderr:
                return {"ok": False, "stage": "connect", "error": f"SSH 연결 거부 — {ip}:22 포트가 닫혀있습니다"}
            if "timed out" in stderr.lower() or "No route" in stderr:
                return {"ok": False, "stage": "network", "error": f"네트워크 도달 불가 — {ip}에 접근할 수 없습니다"}
            if "Host key verification" in stderr:
                return {"ok": False, "stage": "hostkey", "error": f"호스트 키 검증 실패 — known_hosts 문제"}
            return {"ok": False, "stage": "ssh", "error": f"SSH 실패: {stderr[:300]}"}
        if "__ccc_ok__" not in stdout:
            return {"ok": False, "stage": "ssh", "error": f"SSH 응답 이상: {stdout[:200]}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stage": "network", "error": f"SSH 연결 시간 초과 — {ip}에 접근할 수 없습니다"}
    except Exception as e:
        return {"ok": False, "stage": "ssh", "error": str(e)}

    # 2단계: sudo 권한
    try:
        r = subprocess.run(
            ["sshpass", "-p", password, "ssh", *ssh_opts, f"{user}@{ip}",
             f"echo '{password}' | sudo -S whoami 2>&1"],
            capture_output=True, text=True, timeout=15, errors="replace",
        )
        if "not in the sudoers" in r.stdout or "not in the sudoers" in r.stderr:
            return {"ok": False, "stage": "sudo", "error": f"sudo 권한 없음 — {user} 계정이 sudoers에 없습니다"}
        if "root" not in r.stdout:
            combined = (r.stdout + r.stderr)[:300]
            return {"ok": False, "stage": "sudo", "error": f"sudo 실행 실패: {combined}"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "stage": "sudo", "error": "sudo 실행 시간 초과"}
    except Exception as e:
        return {"ok": False, "stage": "sudo", "error": str(e)}

    return {"ok": True, "stage": "ready"}


def ssh_run(ip: str, user: str, password: str, commands: list[str], timeout: int = None) -> dict:
    """SSH로 명령 실행 — scp로 스크립트 업로드 후 실행 (이스케이핑/stdin 문제 원천 해결)"""
    import tempfile
    script = "#!/bin/bash\nset -e\n" + "\n".join(commands) + "\n"
    t = timeout or SSH_TIMEOUT
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

    try:
        # 1. 로컬에 임시 스크립트 파일 생성
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(script)
            local_path = f.name

        remote_path = f"/tmp/ccc_onboard_{os.getpid()}.sh"

        # 2. scp로 스크립트 업로드
        scp_cmd = ["sshpass", "-p", password, "scp", *ssh_opts, local_path, f"{user}@{ip}:{remote_path}"]
        scp_r = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=30, errors="replace")
        os.unlink(local_path)

        if scp_r.returncode != 0:
            return {"success": False, "stdout": "", "stderr": f"scp failed: {scp_r.stderr[:500]}"}

        # 3. ssh로 스크립트 실행 (sudo -S로 비밀번호 전달)
        run_cmd = [
            "sshpass", "-p", password,
            "ssh", *ssh_opts, f"{user}@{ip}",
            f"echo '{password}' | sudo -S bash {remote_path}; rm -f {remote_path}",
        ]
        r = subprocess.run(run_cmd, capture_output=True, text=True, timeout=t, errors="replace")
        stderr = "\n".join(l for l in r.stderr.splitlines()
                           if "password" not in l.lower() and "setlocale" not in l.lower())
        return {"success": r.returncode == 0, "stdout": r.stdout[:5000], "stderr": stderr[:2000]}

    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": f"SSH timeout ({t}s)"}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


# 내부 IP 고정 (API의 INTERNAL_IPS와 동일)
INTERNAL_IPS = {
    "attacker": os.getenv("VM_ATTACKER_IP", "10.20.30.201"),
    "secu":     os.getenv("VM_SECU_IP",     "10.20.30.1"),
    "web":      os.getenv("VM_WEB_IP",      "10.20.30.80"),
    "siem":     os.getenv("VM_SIEM_IP",     "10.20.30.100"),
    "manager":  os.getenv("VM_MANAGER_IP",  "10.20.30.200"),
    "windows":  os.getenv("VM_WINDOWS_IP",  "10.20.30.50"),
    # bastion 자신 — docker.sock RO mount + KG DB 가용. run_command 가 _is_local_ip
    # 확인 후 subprocess 직접 실행 (SubAgent 안 거침). shell skill 의 docker ps /
    # curl localhost API 가 여기로 라우팅 (cycle 2 F2c fix).
    "bastion":  os.getenv("VM_BASTION_IP",  "127.0.0.1"),
}
INTERNAL_SUBNET = os.getenv("VM_INTERNAL_SUBNET", "10.20.30.0/24")
SECU_GW = INTERNAL_IPS["secu"]


def _win_ssh_run(ip: str, user: str, password: str, ps_script: str, timeout: int = 120) -> dict:
    """Windows SSH — PowerShell 스크립트를 scp 업로드 후 실행"""
    import tempfile
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".ps1", delete=False, encoding="utf-8") as f:
            f.write(ps_script)
            local_path = f.name

        # Windows scp는 홈 디렉토리 상대경로만 동작
        remote_file = "ccc_onboard.ps1"
        scp_cmd = ["sshpass", "-p", password, "scp", *ssh_opts, local_path, f"{user}@{ip}:{remote_file}"]
        scp_r = subprocess.run(scp_cmd, capture_output=True, text=True, timeout=30, errors="replace")
        os.unlink(local_path)
        if scp_r.returncode != 0:
            return {"success": False, "stdout": "", "stderr": f"scp failed: {scp_r.stderr[:300]}"}

        run_cmd = [
            "sshpass", "-p", password, "ssh", *ssh_opts, f"{user}@{ip}",
            f"powershell -ExecutionPolicy Bypass -File {remote_file}; del {remote_file}",
        ]
        r = subprocess.run(run_cmd, capture_output=True, text=True, timeout=timeout, errors="replace")
        return {"success": r.returncode == 0, "stdout": r.stdout[:5000], "stderr": r.stderr[:2000]}
    except subprocess.TimeoutExpired:
        return {"success": False, "stdout": "", "stderr": f"SSH timeout ({timeout}s)"}
    except Exception as e:
        return {"success": False, "stdout": "", "stderr": str(e)}


# Windows SubAgent (Python http.server 기반)
WIN_SUBAGENT_SCRIPT = r'''
# Python 확인
$v = & python -c "import sys; print(sys.version)" 2>$null
if (-not $v -or $v -notmatch "\d+\.\d+") {
    Write-Host "ERROR: Python not installed"
    exit 1
}
Write-Host "Python: $v"

$AgentDir = "C:\ccc-subagent"
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null

# SubAgent 스크립트 생성
@"
import json, subprocess, os, platform
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status":"healthy","hostname":platform.node(),"role":"windows"}).encode())
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path == "/a2a/run_script":
            n = int(self.headers.get("Content-Length",0))
            b = json.loads(self.rfile.read(n)) if n else {}
            try:
                r = subprocess.run(b.get("script","echo ok"), shell=True, capture_output=True, text=True, timeout=b.get("timeout",60))
                res = {"exit_code":r.returncode,"stdout":r.stdout[:10000],"stderr":r.stderr[:5000]}
            except Exception as e:
                res = {"exit_code":-1,"stdout":"","stderr":str(e)}
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass
if __name__ == "__main__":
    print("CCC SubAgent listening on :8002")
    HTTPServer(("0.0.0.0", 8002), H).serve_forever()
"@ | Out-File -Encoding utf8 "$AgentDir\agent.py" -Force

# 기존 프로세스 종료
Get-Process python* -ErrorAction SilentlyContinue | Where-Object { $_.Path -and $_.CommandLine -like "*agent.py*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 백그라운드로 즉시 실행
Start-Process -FilePath "python" -ArgumentList "$AgentDir\agent.py" -WorkingDirectory $AgentDir -WindowStyle Hidden
Start-Sleep -Seconds 2

# 시작 프로그램에 등록 (재부팅 시 자동 시작)
$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
@"
@echo off
start /B python $AgentDir\agent.py
"@ | Out-File -Encoding ascii "$StartupDir\ccc-subagent.bat" -Force

# 방화벽 포트 열기
try { New-NetFirewallRule -DisplayName "CCC SubAgent" -Direction Inbound -Protocol TCP -LocalPort 8002 -Action Allow -ErrorAction SilentlyContinue | Out-Null } catch {}

# 확인
$listening = netstat -an | Select-String ":8002"
if ($listening) { Write-Host "CCC SubAgent running on :8002" } else { Write-Host "WARN: SubAgent may not be listening yet" }
'''

WIN_INTERNAL_IP_SCRIPT = r'''
# 두번째 NIC에 내부 IP 설정
$Adapters = Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }} | Sort-Object ifIndex
if ($Adapters.Count -ge 2) {{
    $InternalNic = $Adapters[1]
    New-NetIPAddress -InterfaceIndex $InternalNic.ifIndex -IPAddress "{internal_ip}" -PrefixLength 24 -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Internal NIC: $($InternalNic.Name) = {internal_ip}"
}} else {{
    Write-Host "WARN: second NIC not found"
}}
'''

WIN_NAT_DISABLE_SCRIPT = r'''
# 기본 게이트웨이를 Security GW로 변경
$Adapters = Get-NetAdapter | Where-Object {{ $_.Status -eq "Up" }} | Sort-Object ifIndex
if ($Adapters.Count -ge 1) {{
    # 기존 기본 게이트웨이 삭제
    Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    # Security GW를 기본 게이트웨이로
    New-NetRoute -DestinationPrefix "0.0.0.0/0" -NextHop "{secu_gw}" -InterfaceIndex $Adapters[0].ifIndex -ErrorAction SilentlyContinue | Out-Null
    Write-Host "Default gateway set to {secu_gw}"
}}
'''


def _onboard_windows(ip: str, internal_ip: str, user: str, password: str, results: dict) -> dict:
    """Windows VM 온보딩 — scp로 파일 직접 전송 + PowerShell 실행"""
    import tempfile
    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]

    # 1. SubAgent 설치 — agent.py를 scp로 직접 전송
    agent_py = '''import json, subprocess, os, platform
from http.server import HTTPServer, BaseHTTPRequestHandler
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status":"healthy","hostname":platform.node(),"role":"windows"}).encode())
        else:
            self.send_response(404); self.end_headers()
    def do_POST(self):
        if self.path == "/a2a/run_script":
            n = int(self.headers.get("Content-Length",0))
            b = json.loads(self.rfile.read(n)) if n else {}
            try:
                r = subprocess.run(b.get("script","echo ok"), shell=True, capture_output=True, text=True, timeout=b.get("timeout",60))
                res = {"exit_code":r.returncode,"stdout":r.stdout[:10000],"stderr":r.stderr[:5000]}
            except Exception as e:
                res = {"exit_code":-1,"stdout":"","stderr":str(e)}
            self.send_response(200)
            self.send_header("Content-Type","application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode())
        else:
            self.send_response(404); self.end_headers()
    def log_message(self, *a): pass
if __name__ == "__main__":
    print("CCC SubAgent listening on :8002")
    HTTPServer(("0.0.0.0", 8002), H).serve_forever()
'''
    # agent.py 로컬에 만들어서 scp
    with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8") as f:
        f.write(agent_py)
        local_agent = f.name

    # setup.ps1도 scp
    setup_ps1 = r'''
$AgentDir = "C:\ccc-subagent"
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
Move-Item -Force "$HOME\agent.py" "$AgentDir\agent.py"
Get-Process python* -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*agent.py*" } | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
Start-Process -FilePath "python" -ArgumentList "$AgentDir\agent.py" -WorkingDirectory $AgentDir -WindowStyle Hidden
Start-Sleep -Seconds 2
$StartupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
"@echo off`nstart /B python $AgentDir\agent.py" | Out-File -Encoding ascii "$StartupDir\ccc-subagent.bat" -Force
try { New-NetFirewallRule -DisplayName "CCC SubAgent" -Direction Inbound -Protocol TCP -LocalPort 8002 -Action Allow -ErrorAction SilentlyContinue | Out-Null } catch {}
$listening = netstat -an | Select-String ":8002"
if ($listening) { Write-Host "SubAgent running on :8002" } else { Write-Host "WARN: not listening" }
'''
    try:
        # agent.py 전송
        scp1 = subprocess.run(["sshpass", "-p", password, "scp", *ssh_opts, local_agent, f"{user}@{ip}:agent.py"],
                              capture_output=True, text=True, timeout=30, errors="replace")
        os.unlink(local_agent)
        if scp1.returncode != 0:
            results["steps"].append({"step": "subagent_install", "success": False, "stderr": f"scp agent.py failed: {scp1.stderr[:300]}"})
            return results

        # setup.ps1 실행
        r = _win_ssh_run(ip, user, password, setup_ps1)
        results["steps"].append({"step": "subagent_install", **r})
    except Exception as e:
        results["steps"].append({"step": "subagent_install", "success": False, "stderr": str(e)})

    # 1b. 시각/타임존 설정 — Korea Standard Time + NTP 동기화
    win_tz = (
        'tzutil /s "Korea Standard Time"; '
        'sc config w32time start= auto 2>$null; '
        'net start w32time 2>$null; '
        'w32tm /config /manualpeerlist:"time.windows.com,0x1 time.google.com,0x1" /syncfromflags:manual /reliable:yes /update 2>$null; '
        'w32tm /resync 2>$null; '
        'w32tm /tz; w32tm /query /status 2>$null'
    )
    r_tz = _win_ssh_run(ip, user, password, win_tz)
    results["steps"].append({"step": "time_sync", **r_tz})

    # 2. 내부 IP 설정
    script = WIN_INTERNAL_IP_SCRIPT.format(internal_ip=internal_ip)
    r = _win_ssh_run(ip, user, password, script)
    results["steps"].append({"step": "internal_ip_setup", "ip": internal_ip, **r})

    # 3. NAT disable + Security GW 경유
    script = WIN_NAT_DISABLE_SCRIPT.format(secu_gw=SECU_GW)
    r = _win_ssh_run(ip, user, password, script)
    results["steps"].append({"step": "nat_disable_gw_route", "gateway": SECU_GW, **r})

    # 4. 헬스체크
    import time as _t
    health = {"status": "unreachable"}
    for _ in range(5):
        _t.sleep(2)
        health = health_check(ip)
        if health.get("status") == "healthy":
            break
    results["healthy"] = health.get("status") == "healthy"
    results["steps"].append({"step": "health_check", "success": results["healthy"], "detail": health})

    return results


def onboard_vm(ip: str, role: str, user: str = "ccc", password: str = "1",
               gpu_url: str = "", manager_model: str = "", subagent_model: str = "") -> dict:
    """VM 온보딩 (외부 IP로 SSH 접속)
    1. SubAgent 설치
    2. 역할별 소프트웨어 설치
    3. 내부 NIC에 고정 IP 설정
    4. Security GW 제외 — NAT disable + 기본 게이트웨이를 Security GW로 변경
    5. 헬스체크
    """
    internal_ip = INTERNAL_IPS.get(role, "10.20.30.250")
    results = {"ip": ip, "internal_ip": internal_ip, "role": role, "steps": []}

    # Windows — 자동 온보딩 미지원
    if role == "windows":
        results["steps"].append({
            "step": "skip", "success": True,
            "stdout": "Windows는 수동 설정 필요. SubAgent를 직접 실행하세요.",
        })
        health = health_check(ip)
        results["healthy"] = health.get("status") == "healthy"
        results["steps"].append({"step": "health_check", "success": results["healthy"], "detail": health})
        return results

    # ── SSH 연결 + sudo 사전 검증 ──
    pre = ssh_test(ip, user, password)
    if not pre["ok"]:
        results["steps"].append({"step": f"{pre['stage']}_verify", "success": False, "stderr": pre["error"]})
        results["healthy"] = False
        results["error"] = pre["error"]
        return results
    results["steps"].append({"step": "ssh_sudo_verify", "success": True})

    # 0. 재온보딩 시 인터넷 접근 보장 — 외부 NIC의 DHCP GW 복구
    if role != "secu":
        restore_gw = """
# 인터넷 접근 확인 → 안 되면 외부 NIC DHCP GW 복구
if ! curl -s --connect-timeout 3 http://archive.ubuntu.com/ >/dev/null 2>&1; then
    EXT_IF=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{print $2}' | tr -d ':' | head -1)
    # DHCP 릴리스에서 GW 찾기
    GW=$(grep -h 'option routers' /var/lib/dhcp/dhclient*.leases /var/lib/NetworkManager/*.lease 2>/dev/null | tail -1 | awk '{print $3}' | tr -d ';')
    # 못 찾으면 서브넷의 .2 시도 (VMware 기본)
    if [ -z "$GW" ]; then
        SUBNET=$(ip -o addr show dev $EXT_IF 2>/dev/null | awk '{print $4}' | head -1 | sed 's|\\.[0-9]*/.*|.2|')
        GW=$SUBNET
    fi
    if [ -n "$GW" ] && [ -n "$EXT_IF" ]; then
        ip route add default via $GW dev $EXT_IF metric 50 2>/dev/null || true
        echo "Restored GW: $GW via $EXT_IF"
    fi
fi
"""
        ssh_run(ip, user, password, [restore_gw], timeout=20)

    # 1. SubAgent 설치 (외부 IP로 SSH — 인터넷 필요)
    install_script = SUBAGENT_INSTALL_SCRIPT.replace("{role}", role)
    r = ssh_run(ip, user, password, [install_script], timeout=120)
    results["steps"].append({"step": "subagent_install", **r})
    if not r["success"]:
        results["healthy"] = False
        results["error"] = f"SubAgent 설치 실패: {r.get('stderr', '')[:300]}"
        return results

    # 1b. 시각/타임존 설정 — Asia/Seoul (UTC+9) + NTP 동기화
    # 모든 VM 의 로그·이벤트 시간을 일관되게 만들어 SIEM 상관분석·conntrack·디지털 포렌식의 시계 어긋남 방지.
    tz_script = """
timedatectl set-timezone Asia/Seoul 2>/dev/null || true
# systemd-timesyncd 활성화 (Ubuntu/Debian 기본)
if systemctl list-unit-files 2>/dev/null | grep -q '^systemd-timesyncd'; then
    systemctl enable --now systemd-timesyncd 2>/dev/null || true
    timedatectl set-ntp true 2>/dev/null || true
elif command -v chronyd >/dev/null 2>&1; then
    systemctl enable --now chronyd 2>/dev/null || systemctl enable --now chrony 2>/dev/null || true
else
    # systemd-timesyncd 없는 경우 chrony 설치 시도
    apt-get install -y chrony 2>/dev/null && systemctl enable --now chrony 2>/dev/null || true
fi
echo "[time] 현재 시각 + 동기화 상태:"
timedatectl 2>/dev/null | grep -E 'Time zone|System clock synchronized|NTP service' || date
"""
    r_tz = ssh_run(ip, user, password, [tz_script], timeout=60)
    results["steps"].append({"step": "time_sync", **r_tz})

    # 2. 역할별 소프트웨어 설치
    role_cmds = list(ROLE_SETUP_SCRIPTS.get(role, []))

    # web: vuln-sites 소스코드 업로드 (5종 docker compose) — SUBAGENT_INSTALL 후 실행 가능
    # ccc-api 가 contents/vuln-sites/ 를 base64 tar 로 업로드 → /opt/vuln-sites/ 풀어둠.
    # 이후 role_setup 의 docker-compose up 단계에서 사용.
    if role == "web":
        try:
            import os as _os, base64 as _b64, tarfile as _tar, io as _io
            # ccc 루트 추정 — 이 파일 기준 ../../..
            _ccc_root = _os.path.dirname(_os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
            _vuln_src = _os.path.join(_ccc_root, "contents", "vuln-sites")
            if _os.path.isdir(_vuln_src):
                _buf = _io.BytesIO()
                with _tar.open(fileobj=_buf, mode="w:gz") as _t:
                    _t.add(_vuln_src, arcname="vuln-sites")
                _b64data = _b64.b64encode(_buf.getvalue()).decode()
                _upload = (
                    f"mkdir -p /opt/vuln-sites && "
                    f"echo '{_b64data}' | base64 -d > /tmp/vuln-sites.tar.gz && "
                    f"tar xzf /tmp/vuln-sites.tar.gz -C /opt/vuln-sites/ --strip-components=1 && "
                    f"rm /tmp/vuln-sites.tar.gz && "
                    f"echo 'vuln-sites src uploaded:' && ls /opt/vuln-sites/"
                )
                role_cmds.insert(0, _upload)
        except Exception as _e:
            results["steps"].append({"step": "vuln_sites_upload_skip", "success": True, "stdout": str(_e)[:200]})

    # manager: 외부 LLM 서버 있으면 Ollama 스킵, 없으면 로컬 설치
    if role == "manager":
        llm_url = gpu_url or f"http://localhost:11434"
        m_model = manager_model or LLM_MANAGER_MODEL
        s_model = subagent_model or LLM_SUBAGENT_MODEL

        if not gpu_url:
            # 외부 LLM 없음 → 로컬 Ollama 설치 + 모델 pull
            role_cmds.insert(0, "curl -fsSL https://ollama.ai/install.sh | sh")
            role_cmds.append(f"ollama pull {m_model}")
            role_cmds.append(f"ollama pull {s_model}")

        # bastion .env 생성 (LLM + VM IP)
        role_cmds.append(
            f"cat > /opt/bastion/.env << ENVEOF\n"
            f"LLM_BASE_URL={llm_url}\n"
            f"LLM_MANAGER_MODEL={m_model}\n"
            f"LLM_SUBAGENT_MODEL={s_model}\n"
            f"VM_ATTACKER_IP={INTERNAL_IPS['attacker']}\n"
            f"VM_SECU_IP={INTERNAL_IPS['secu']}\n"
            f"VM_WEB_IP={INTERNAL_IPS['web']}\n"
            f"VM_SIEM_IP={INTERNAL_IPS['siem']}\n"
            f"VM_MANAGER_IP={INTERNAL_IPS['manager']}\n"
            f"ENVEOF"
        )

    if role_cmds:
        t = 600 if role == "siem" else 300 if role == "manager" and not gpu_url else 180
        r = ssh_run(ip, user, password, role_cmds, timeout=t)
        results["steps"].append({"step": "role_setup", **r})
        # role_setup 실패는 경고만 (SubAgent는 이미 설치됨, 계속 진행)

    # 3. 내부 NIC IP 설정 — 런타임 적용 + netplan 영구화 (reboot 시 IP 사라지는 버그 fix 2026-04-29)
    internal_script = f"""
IFACE=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{{print $2}}' | tr -d ':' | tail -1)
if [ -n "$IFACE" ]; then
    ip addr add {internal_ip}/24 dev $IFACE 2>/dev/null || true
    ip link set $IFACE up
    # netplan 영구화 — reboot 후에도 IP 유지
    if [ -d /etc/netplan ]; then
        cat > /etc/netplan/90-ccc-internal.yaml << NETPLAN_EOF
network:
  version: 2
  ethernets:
    $IFACE:
      dhcp4: false
      addresses: [{internal_ip}/24]
NETPLAN_EOF
        chmod 600 /etc/netplan/90-ccc-internal.yaml
        netplan apply 2>&1 | head -3 || true
        echo "Internal NIC persisted via netplan: $IFACE = {internal_ip}"
    else
        echo "Internal NIC (runtime only): $IFACE = {internal_ip}"
    fi
else
    echo "WARN: second NIC not found"
fi
"""
    r = ssh_run(ip, user, password, [internal_script])
    results["steps"].append({"step": "internal_ip_setup", "ip": internal_ip, **r})

    # 4. NAT disable + Security GW 경유 + DNS 설정
    if role != "secu":
        nat_script = f"""
ip route del default 2>/dev/null || true
ip route add default via {SECU_GW} 2>/dev/null || true
echo "Default gateway set to {SECU_GW}"
# DNS → secu
mkdir -p /etc/systemd/resolved.conf.d
cat > /etc/systemd/resolved.conf.d/ccc.conf << 'RESEOF'
[Resolve]
DNS=10.20.30.1
FallbackDNS=8.8.8.8
RESEOF
systemctl restart systemd-resolved 2>/dev/null || true
echo "DNS set to {SECU_GW}"
"""
        r = ssh_run(ip, user, password, [nat_script])
        results["steps"].append({"step": "nat_disable_gw_route", "gateway": SECU_GW, **r})
    else:
        # secu — NAT masquerade + 외부 NIC port forwarding (Wazuh/OpenCTI/JuiceShop/vuln-sites)
        web_ip = INTERNAL_IPS.get("web", "10.20.30.80")
        siem_ip = INTERNAL_IPS.get("siem", "10.20.30.100")
        secu_script = f"""
# 1. ip_forward 영구화
echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-ccc-secu.conf
echo 'net.ipv4.conf.all.proxy_arp=1' >> /etc/sysctl.d/99-ccc-secu.conf
sysctl -p /etc/sysctl.d/99-ccc-secu.conf

# 2. nft table/chain idempotent 생성
EXTERNAL=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{{print $2}}' | tr -d ':' | head -1)
nft add table ip nat 2>/dev/null || true
nft 'add chain ip nat prerouting {{ type nat hook prerouting priority dstnat; }}' 2>/dev/null || true
nft 'add chain ip nat postrouting {{ type nat hook postrouting priority srcnat; }}' 2>/dev/null || true

# 3. 외부 NIC port forwarding (학생/관리자 외부 접근용) — 멱등 추가
add_dnat() {{
    local port="$1"; local target="$2"
    if ! nft list chain ip nat prerouting 2>/dev/null | grep -q "iifname \\"$EXTERNAL\\" tcp dport $port dnat to $target"; then
        nft add rule ip nat prerouting iifname "$EXTERNAL" tcp dport $port dnat to "$target"
    fi
}}
# JuiceShop / web port 80
add_dnat 80   "{web_ip}:80"
# Wazuh Dashboard (HTTPS) → siem
add_dnat 443  "{siem_ip}:443"
# OpenCTI → siem
add_dnat 8080 "{siem_ip}:8080"
# Wazuh Manager Agent / API ports → siem (학생 SubAgent 등록 가능)
add_dnat 1514 "{siem_ip}:1514"
add_dnat 1515 "{siem_ip}:1515"
add_dnat 55000 "{siem_ip}:55000"
# vuln-sites (NeoBank/GovPortal/MediForum/AdminConsole/AICompanion) → web (web 에 docker 배포 가정)
add_dnat 3001 "{web_ip}:3001"
add_dnat 3002 "{web_ip}:3002"
add_dnat 3003 "{web_ip}:3003"
add_dnat 3004 "{web_ip}:3004"
add_dnat 3005 "{web_ip}:3005"

# 4. masquerade — internal → external 응답 NAT
if ! nft list chain ip nat postrouting 2>/dev/null | grep -q "oifname \\"$EXTERNAL\\" masquerade"; then
    nft add rule ip nat postrouting oifname "$EXTERNAL" masquerade
fi
# internal 응답 시 source NAT (DNAT 된 패킷 회신용)
if ! nft list chain ip nat postrouting 2>/dev/null | grep -q "ip daddr 10.20.30.0/24 oifname"; then
    INTERNAL=$(ip -o link show | grep -v 'lo\\|docker\\|veth' | awk '{{print $2}}' | tr -d ':' | tail -1)
    [ -n "$INTERNAL" ] && nft add rule ip nat postrouting ip daddr 10.20.30.0/24 oifname "$INTERNAL" masquerade
fi

# 5. nft 규칙 영구화
nft list ruleset > /etc/nftables.conf
systemctl enable nftables 2>/dev/null || true

echo "secu port forwarding: $EXTERNAL → web/siem/vuln-sites configured"
nft list chain ip nat prerouting | grep dnat | head -15
"""
        r = ssh_run(ip, user, password, [secu_script])
        results["steps"].append({"step": "secu_nat_forward", **r})

    # 5. 헬스체크 — SubAgent 시작 대기 후 확인 (외부 IP 우선)
    import time as _t
    health = {"status": "unreachable"}
    for attempt in range(5):
        _t.sleep(2)
        health = health_check(ip)  # 외부 IP로 확인
        if health.get("status") == "healthy":
            break
    if health.get("status") != "healthy":
        health = health_check(internal_ip)  # 외부 안되면 내부 시도
    results["healthy"] = health.get("status") == "healthy"
    results["steps"].append({"step": "health_check", "success": results["healthy"], "detail": health})

    return results


# ── SubAgent Communication (A2A) ─────────────────

def health_check(ip: str) -> dict:
    """SubAgent 헬스체크.

    바스티온 자신(로컬 IP)은 SubAgent가 없으므로 healthy로 즉답.
    """
    if _is_local_ip(ip):
        return {"status": "healthy", "hostname": "bastion", "role": "manager", "local": True}
    try:
        r = httpx.get(f"http://{ip}:{SUBAGENT_PORT}/health", timeout=5.0)
        return r.json()
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}


_LOCAL_IPS = {"127.0.0.1", "localhost", "0.0.0.0", "::1"}


def _is_local_ip(ip: str) -> bool:
    """IP가 이 호스트 자신인지 판정 — 127.x, 바스티온 자체 내부/외부 IP 포함."""
    if not ip or ip in _LOCAL_IPS:
        return True
    try:
        import subprocess as _sp
        out = _sp.run(["ip", "-4", "-o", "addr"], capture_output=True, text=True, timeout=2)
        if out.returncode == 0 and ip in out.stdout:
            return True
    except Exception:
        pass
    return False


def run_command(ip: str, script: str, timeout: int = 60) -> dict:
    """대상 VM에 명령 실행.

    - IP가 로컬(바스티온 자신)이면 subprocess로 직접 실행
    - 그 외에는 SubAgent(/a2a/run_script)로 위임
    """
    if _is_local_ip(ip):
        try:
            import subprocess as _sp, os as _os
            # ★ bastion-autopilot cycle 8 (2026-05-18) fix F5:
            #   uvicorn 이 root user (entrypoint default) → subprocess ssh 시 root 의
            #   ~/.ssh/config 안 봄 → ccc 의 el34-fw alias 무지 → root 로 시도 → Permission
            #   denied. ccc user 로 강제 실행 (su - ccc -c) — ccc 의 .ssh/config + id_rsa
            #   가용. 모든 local subprocess 명령 동일 적용.
            _ssh_user = _os.getenv("SSH_USER", "ccc")
            # ★ bastion-autopilot cycle 3 (2026-05-18) F6: ssh 호출 시 -tt 자동 주입.
            # web 의 sudoers `Defaults use_pty` 가 non-tty subprocess 의 sudo 차단
            # → ssh -tt 로 force tty allocation. 학생 PC autopilot subprocess (stdin
            # 없음) 시 안전. 모든 sudo 통한 명령 호환성.
            _script = script
            if " ssh " in f" {_script} " or _script.startswith("ssh "):
                # `ssh ` 단어 가 첫 위치 또는 어떤 토큰 으로 등장 시 -tt 추가
                import re as _re
                _script = _re.sub(r'\bssh (?!-)', 'ssh -tt ', _script, count=1)
                # 이미 -n 이 있으면 -tt 와 충돌 → -n 제거 (autopilot 의 stdin 부재)
                _script = _script.replace('-n -tt ', '-tt ').replace('-tt -n ', '-tt ')
            if _ssh_user and _ssh_user != "root":
                # quoted command — single-quote 안 의 '" 처리
                _esc = _script.replace("'", "'\\''")
                _cmd = ["su", "-", _ssh_user, "-c", f"bash -c '{_esc}'"]
            else:
                _cmd = ["bash", "-c", _script]
            r = _sp.run(_cmd, capture_output=True, text=True, timeout=timeout)
            return {
                "exit_code": r.returncode,
                "stdout": r.stdout,
                "stderr": r.stderr,
            }
        except Exception as e:
            return {"exit_code": -1, "stdout": "", "stderr": f"local exec: {e}"}
    try:
        r = httpx.post(
            f"http://{ip}:{SUBAGENT_PORT}/a2a/run_script",
            json={"script": script, "timeout": timeout},
            timeout=float(timeout + 5),
        )
        return r.json()
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


def audit_start(ip: str, session_id: str, lab_id: str = "", student_id: str = "") -> dict:
    """SubAgent 의 audit 세션 시작 — 학생 lab 명령 캡처 활성.

    로컬 IP 일 경우는 SubAgent 가 같은 호스트에 있다는 가정 (바스티온 자체).
    호환성 위해 SubAgent 미배포 환경에서는 stub 반환.
    """
    try:
        r = httpx.post(
            f"http://{ip}:{SUBAGENT_PORT}/a2a/audit/start",
            json={"session_id": session_id, "lab_id": lab_id, "student_id": student_id},
            timeout=10.0,
        )
        if r.status_code == 200:
            return r.json()
        return {"status": "error", "detail": f"http {r.status_code}: {r.text[:200]}"}
    except Exception as e:
        return {"status": "unavailable", "detail": str(e)}


def audit_run(ip: str, session_id: str, script: str, timeout: int = 30) -> dict:
    """audit 세션 안에서 명령 실행 — SubAgent 가 자동 transcript 누적."""
    try:
        r = httpx.post(
            f"http://{ip}:{SUBAGENT_PORT}/a2a/audit/run",
            json={"session_id": session_id, "script": script, "timeout_s": timeout},
            timeout=float(timeout + 5),
        )
        if r.status_code == 200:
            return r.json()
        return {"status": "error", "exit_code": -1, "stdout": "", "stderr": f"http {r.status_code}"}
    except Exception as e:
        return {"status": "error", "exit_code": -1, "stdout": "", "stderr": str(e)}


def audit_stop(ip: str, session_id: str) -> dict:
    """audit 세션 종료 — SubAgent 가 캡처한 transcript 반환."""
    try:
        r = httpx.post(
            f"http://{ip}:{SUBAGENT_PORT}/a2a/audit/stop",
            json={"session_id": session_id},
            timeout=10.0,
        )
        if r.status_code == 200:
            return r.json()
        return {"status": "error", "transcript": {"commands": []}}
    except Exception as e:
        return {"status": "unavailable", "transcript": {"commands": []}, "detail": str(e)}


def system_status(infras: list[dict]) -> dict:
    """전체 인프라 상태 요약"""
    status = {"total": len(infras), "healthy": 0, "unreachable": 0, "details": []}
    for infra in infras:
        ip = infra.get("ip", "")
        h = health_check(ip)
        is_healthy = h.get("status") == "healthy"
        if is_healthy:
            status["healthy"] += 1
        else:
            status["unreachable"] += 1
        status["details"].append({"ip": ip, "role": infra.get("role", ""), **h})
    return status


# ── LLM 기반 스킬 디스패치 (bastion의 skill system 참고) ──

SKILLS = {
    "ccc": {
        "description": "CCC 플랫폼 관리 — action: start, stop, restart, status, logs, build_ui, start_api, stop_api, restart_api, start_db, stop_db, reset_db, backup_db, env, set_env, update, deploy, create_admin, student_list, firewall_open, firewall_close, check_port",
        "requires": ["action"],
    },
    "shell": {
        "description": "이 서버에서 로컬 쉘 명령 실행 (파일 조회, 패키지 설치, 프로세스 관리 등 ccc 스킬에 없는 모든 작업)",
        "requires": ["command"],
    },
    "onboard": {
        "description": "학생 VM에 SubAgent 설치 및 역할별 소프트웨어 배포",
        "requires": ["ip", "role", "ssh_user", "ssh_password"],
    },
    "health_check": {
        "description": "SubAgent 상태 확인",
        "requires": ["ip"],
    },
    "run_command": {
        "description": "원격 VM의 SubAgent에 명령 실행 (A2A 프로토콜)",
        "requires": ["ip", "script"],
    },
    "system_status": {
        "description": "전체 학생 인프라 상태 요약",
        "requires": ["infras"],
    },
    "diagnose": {
        "description": "VM 문제 진단 — 상태 수집 + LLM 분석 + 해결 방안",
        "requires": ["ip", "symptoms"],
    },
}


# ── Local Shell ───────────────────────────────────

def shell_exec(command: str, timeout: int = 60) -> dict:
    """로컬 쉘 명령 실행"""
    try:
        r = subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=CCC_DIR,
        )
        return {"exit_code": r.returncode, "stdout": r.stdout[:10000], "stderr": r.stderr[:5000]}
    except subprocess.TimeoutExpired:
        return {"exit_code": -1, "stdout": "", "stderr": "timeout"}
    except Exception as e:
        return {"exit_code": -1, "stdout": "", "stderr": str(e)}


# ── CCC Platform Management ───────────────────────

_VENV = f"source {CCC_DIR}/.venv/bin/activate 2>/dev/null"
_ENVLOAD = f"set -a; [ -f {CCC_DIR}/.env ] && source {CCC_DIR}/.env; set +a; export PYTHONPATH={CCC_DIR}"
_API_START = f"{_VENV}; {_ENVLOAD}; nohup python3 -m uvicorn apps.ccc_api.src.main:app --host 0.0.0.0 --port 9100 > /tmp/ccc-api.log 2>&1 & echo \"API started (pid: $!)\""
_API_KEY = os.getenv("CCC_API_KEY", "ccc-api-key-2026")


def ccc_manage(action: str, params: dict = None) -> dict:
    """CCC 플랫폼 통합 관리"""
    params = params or {}
    actions = {
        # ── 서비스 시작/중지 ──
        "start": f"cd {CCC_DIR} && docker compose -f docker/docker-compose.yaml up -d postgres && sleep 2 && {_API_START}",
        "stop": f"pkill -f 'uvicorn apps.ccc_api' 2>/dev/null; cd {CCC_DIR} && docker compose -f docker/docker-compose.yaml stop; echo 'All stopped'",
        "restart": f"pkill -f 'uvicorn apps.ccc_api' 2>/dev/null; sleep 1; cd {CCC_DIR} && {_API_START}",
        "start_api": f"cd {CCC_DIR} && {_API_START}",
        "stop_api": "pkill -f 'uvicorn apps.ccc_api' && echo 'API stopped' || echo 'API not running'",
        "restart_api": f"pkill -f 'uvicorn apps.ccc_api' 2>/dev/null; sleep 1; cd {CCC_DIR} && {_API_START}",
        "start_db": f"cd {CCC_DIR} && docker compose -f docker/docker-compose.yaml up -d postgres && echo 'DB started'",
        "stop_db": f"cd {CCC_DIR} && docker compose -f docker/docker-compose.yaml stop postgres && echo 'DB stopped'",

        # ── 상태/로그 ──
        "status":
            "echo '=== CCC Platform Status ==='; echo; "
            "echo '-- Processes --'; "
            "(pgrep -fa 'uvicorn apps.ccc_api' && echo '  API: RUNNING') || echo '  API: STOPPED'; "
            "(docker ps --format '  DB:  RUNNING ({{.Names}} {{.Status}})' 2>/dev/null | grep postgres) || echo '  DB:  STOPPED'; "
            "echo; echo '-- Health --'; "
            f"curl -s -o /dev/null -w '  API response: %{{http_code}}' http://localhost:9100/api/dashboard -H 'X-API-Key: {_API_KEY}' 2>/dev/null; echo; "
            f"curl -s -o /dev/null -w '  LLM response: %{{http_code}}' {LLM_BASE_URL}/api/tags 2>/dev/null; echo; "
            "echo; echo '-- Resources --'; "
            "df -h / | tail -1 | awk '{print \"  Disk: \" $3 \"/\" $2 \" (\" $5 \" used)\"}'; "
            "free -h | awk '/Mem/{print \"  RAM:  \" $3 \"/\" $2}'; "
            f"echo; echo '-- Config --'; "
            f"echo '  CCC_DIR: {CCC_DIR}'; "
            f"echo '  LLM: {LLM_BASE_URL} / {LLM_MODEL}'; "
            f"echo '  DB: {os.getenv('DATABASE_URL', 'postgresql://ccc:ccc@127.0.0.1:5434/ccc')}'",
        "logs": "tail -100 /tmp/ccc-api.log 2>/dev/null || echo 'No API log file. Start API first.'",
        "logs_follow": "tail -f /tmp/ccc-api.log 2>/dev/null || echo 'No API log file'",
        "logs_error": "grep -i 'error\\|traceback\\|exception' /tmp/ccc-api.log 2>/dev/null | tail -30 || echo 'No errors found'",

        # ── UI 빌드/배포 ──
        "build_ui": f"cd {CCC_DIR}/apps/ccc-ui && npm run build 2>&1 && echo 'UI build complete'",
        "deploy": f"cd {CCC_DIR} && git pull && "
            f"cd apps/ccc-ui && npm install && npm run build && cd ../.. && "
            f"{_VENV} && pip install -r requirements.txt -q && "
            f"pkill -f 'uvicorn apps.ccc_api' 2>/dev/null; sleep 1 && {_API_START} && echo 'Deploy complete'",
        "update": f"cd {CCC_DIR} && git pull && echo 'Code updated. Run: ccc restart'",

        # ── DB 관리 ──
        "reset_db": f"cd {CCC_DIR} && docker compose -f docker/docker-compose.yaml stop postgres && "
            "docker compose -f docker/docker-compose.yaml rm -f postgres && "
            "docker volume rm docker_ccc-pgdata 2>/dev/null; "
            "docker compose -f docker/docker-compose.yaml up -d postgres && echo 'DB reset complete. Restart API to recreate tables.'",
        "backup_db": f"mkdir -p {CCC_DIR}/db_backup && docker exec $(docker ps -qf name=postgres) pg_dump -U ccc ccc > {CCC_DIR}/db_backup/backup_$(date +%Y%m%d_%H%M%S).sql && echo 'Backup saved'",
        "db_shell": f"docker exec -it $(docker ps -qf name=postgres) psql -U ccc ccc",

        # ── 환경 설정 ──
        "env": f"cat {CCC_DIR}/.env 2>/dev/null || echo 'No .env file'",
        "set_env": _set_env_cmd(params),

        # ── 사용자 관리 ──
        "create_admin": f"cd {CCC_DIR} && {_VENV}; {_ENVLOAD}; python3 -c \""
            f"import httpx; r=httpx.post('http://localhost:9100/api/auth/create-admin', json={{"
            f"'student_id':'{params.get('id', 'admin')}','name':'{params.get('name', 'Admin')}','password':'{params.get('password', 'admin')}'}},"
            f"headers={{'X-API-Key':'{_API_KEY}'}}); print(r.json())\"",
        "student_list": f"curl -s http://localhost:9100/api/students -H 'X-API-Key: {_API_KEY}' 2>/dev/null | python3 -m json.tool || echo 'API unreachable'",

        # ── 네트워크/방화벽 ──
        "firewall_open": f"sudo ufw allow {params.get('port', '9100')}/tcp && echo 'Port {params.get('port', '9100')} opened'",
        "firewall_close": f"sudo ufw deny {params.get('port', '9100')}/tcp && echo 'Port {params.get('port', '9100')} closed'",
        "check_port": f"ss -tlnp | grep ':{params.get('port', '9100')}' || echo 'Port {params.get('port', '9100')} not listening'",
        "firewall_status": "sudo ufw status verbose 2>/dev/null || echo 'ufw not available'",
    }
    cmd = actions.get(action)
    if not cmd:
        available = ", ".join(sorted(actions.keys()))
        return {"exit_code": 1, "stdout": "", "stderr": f"Unknown action: {action}\nAvailable: {available}"}
    return shell_exec(cmd, timeout=60)


def _set_env_cmd(params: dict) -> str:
    """환경 변수 설정 명령 생성"""
    key = params.get("key", "")
    value = params.get("value", "")
    if not key:
        return "echo 'key 파라미터 필요'"
    return (
        f"grep -q '^{key}=' {CCC_DIR}/.env 2>/dev/null && "
        f"sed -i 's|^{key}=.*|{key}={value}|' {CCC_DIR}/.env || "
        f"echo '{key}={value}' >> {CCC_DIR}/.env; "
        f"echo '{key}={value} saved. Restart API to apply.'"
    )


# 하위호환
def service_manage(action: str) -> dict:
    return ccc_manage(action)


def dispatch_skill(skill_name: str, params: dict) -> dict:
    """스킬 디스패치 — bastion의 tool dispatch 패턴 참고"""
    if skill_name == "shell":
        return shell_exec(params.get("command", "echo 'no command'"), params.get("timeout", 60))
    elif skill_name in ("ccc", "service"):
        return ccc_manage(params.get("action", "status"), params)
    elif skill_name == "onboard":
        return onboard_vm(
            ip=params["ip"], role=params["role"],
            user=params.get("ssh_user", "ccc"),
            password=params.get("ssh_password", "1"),
        )
    elif skill_name == "health_check":
        return health_check(params["ip"])
    elif skill_name == "run_command":
        return run_command(params["ip"], params["script"], params.get("timeout", 60))
    elif skill_name == "system_status":
        return system_status(params["infras"])
    elif skill_name == "diagnose":
        return diagnose_vm(params["ip"], params.get("symptoms", ""))
    else:
        return {"error": f"Unknown skill: {skill_name}"}


def diagnose_vm(ip: str, symptoms: str) -> dict:
    """VM 문제 진단 — 상태 수집 후 LLM 분석"""
    # 1. 상태 수집
    health = health_check(ip)
    collected = {"health": health, "symptoms": symptoms}

    if health.get("status") == "healthy":
        # SubAgent가 살아있으면 추가 정보 수집
        collected["uptime"] = run_command(ip, "uptime")
        collected["disk"] = run_command(ip, "df -h /")
        collected["memory"] = run_command(ip, "free -h")
        collected["services"] = run_command(ip, "systemctl list-units --failed --no-pager")

    # 2. LLM 분석
    prompt = build_system_prompt(f"진단 대상 VM: {ip}\n수집된 상태:\n{json.dumps(collected, ensure_ascii=False, indent=2)}")
    try:
        r = httpx.post(f"{LLM_BASE_URL}/api/chat", json={
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"이 VM의 문제를 진단하고 해결 방안을 제시하세요.\n증상: {symptoms}"},
            ],
            "stream": False,
            "options": {"temperature": 0.3, "num_predict": 800},
        }, timeout=60.0)
        diagnosis = r.json().get("message", {}).get("content", "진단 실패")
    except Exception as e:
        diagnosis = f"LLM 연결 실패: {e}"

    return {"ip": ip, "collected": collected, "diagnosis": diagnosis}


# ── Agent Task 실행 (LLM + 스킬 연동) ────────────

def execute_task(instruction: str, context: dict = None) -> dict:
    """자연어 지시 → LLM이 스킬 선택 → 실행 → 결과 반환

    bastion의 query loop 패턴을 단순화:
    1. 사용자 지시 + 컨텍스트를 LLM에 전달
    2. LLM이 실행할 스킬과 파라미터를 JSON으로 응답
    3. 스킬 실행 후 결과를 반환
    """
    context = context or {}
    skill_list = json.dumps(SKILLS, ensure_ascii=False, indent=2)

    prompt = build_system_prompt(f"사용 가능한 스킬:\n{skill_list}\n\n컨텍스트: {json.dumps(context, ensure_ascii=False)}")

    try:
        r = httpx.post(f"{LLM_BASE_URL}/api/chat", json={
            "model": LLM_MODEL,
            "messages": [
                {"role": "system", "content": prompt},
                {"role": "user", "content": f"""지시: {instruction}

반드시 아래 JSON 형식으로만 응답:
{{"skill": "스킬명", "params": {{...}}, "reason": "선택 이유"}}

스킬이 필요없으면:
{{"skill": "none", "params": {{}}, "reason": "직접 답변", "answer": "답변 내용"}}"""},
            ],
            "stream": False,
            "options": {"temperature": 0.1},
        }, timeout=30.0)
        reply = r.json().get("message", {}).get("content", "{}")
    except Exception as e:
        return {"error": f"LLM 연결 실패: {e}", "instruction": instruction}

    # JSON 파싱
    try:
        # LLM 응답에서 JSON 추출
        import re
        match = re.search(r'\{[\s\S]*\}', reply)
        if match:
            plan = json.loads(match.group())
        else:
            return {"error": "LLM 응답 파싱 실패", "raw": reply}
    except json.JSONDecodeError:
        return {"error": "JSON 파싱 실패", "raw": reply}

    skill_name = plan.get("skill", "none")
    if skill_name == "none":
        return {"answer": plan.get("answer", reply), "reason": plan.get("reason", "")}

    # 스킬 실행
    result = dispatch_skill(skill_name, plan.get("params", {}))
    return {"skill": skill_name, "reason": plan.get("reason", ""), "result": result}
