#!/bin/bash
set -e

SSH_USER="${SSH_USER:-ccc}"
SSH_PASS="${SSH_PASS:-ccc}"
WAZUH_MANAGER="${WAZUH_MANAGER:-10.20.32.100}"
FW_PIPE_IP="${FW_PIPE_IP:-10.20.31.1}"

if ! id "$SSH_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo "$SSH_USER"
    echo "${SSH_USER}:${SSH_PASS}" | chpasswd
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$SSH_USER
fi

# bastion pubkey → ccc authorized_keys (ProxyJump 의 2-hop)
if [ -f /keys/id_rsa.pub ]; then
    mkdir -p /home/$SSH_USER/.ssh
    cat /keys/id_rsa.pub > /home/$SSH_USER/.ssh/authorized_keys
    chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh
    chmod 700 /home/$SSH_USER/.ssh
    chmod 600 /home/$SSH_USER/.ssh/authorized_keys
    echo "[ips] authorized_keys deployed — bastion 의 password-less ssh 가능"
fi

# ─── Routing: ext (10.20.30/24) -> back via fw on pipe ────
echo "[ips] adding return route to ext via fw $FW_PIPE_IP"
ip route add 10.20.30.0/24 via "$FW_PIPE_IP" 2>/dev/null || true

# ─── 출처 IP 보존 vs (legacy) masquerade ──────────────────
# PRESERVE_SRC_IP=1 (기본): masquerade 안 함 → 공격자 출처(.202)가 web/ModSec 까지 보존.
#   리턴 경로는 default GW=fw 로 보장: web→ips→fw→host(conntrack 역-DNAT)→.202.
DMZ_IFACE=$(ip -o -4 addr show | awk '$4 ~ /^10\.20\.32\./ {print $2; exit}')
if [ "${PRESERVE_SRC_IP:-1}" = "1" ]; then
    echo "[ips] PRESERVE_SRC_IP=1 → masquerade 비활성, default GW = fw ($FW_PIPE_IP) for return path"
    ip route replace default via "$FW_PIPE_IP" 2>/dev/null || true
else
    echo "[ips] (legacy) enabling NAT masquerade on dmz NIC $DMZ_IFACE"
    nft "add table ip nat6v6" 2>/dev/null || true
    nft "add chain ip nat6v6 postrouting { type nat hook postrouting priority 100 ; }" 2>/dev/null || true
    nft "add rule ip nat6v6 postrouting oifname \"$DMZ_IFACE\" ip saddr 10.20.30.0/24 masquerade" 2>/dev/null || true
    nft "add rule ip nat6v6 postrouting oifname \"$DMZ_IFACE\" ip saddr 10.20.31.0/24 masquerade" 2>/dev/null || true
fi
# int (10.20.40/24) is reached via web (dmz NIC = 10.20.32.80) — but web does L7
# proxy, not L3 forward. ips doesn't need a route to int — incoming TCP to dmz
# 10.20.32.80 (web) terminates there.

# ─── Suricata 룰 update + sniff both pipe + dmz ────────────
echo "[ips] updating Suricata rules (5-10s)"
suricata-update --no-test 2>&1 | tail -3 || true

if ! grep -q 'local.rules' /etc/suricata/suricata.yaml; then
    sed -i 's|^rule-files:|rule-files:\n  - local.rules|' /etc/suricata/suricata.yaml || true
fi

# secuops/W05-S5 (suppress/threshold.config) 동작 보장 — default 주석 해제
sed -i 's|^# threshold-file:|threshold-file:|' /etc/suricata/suricata.yaml || true
# 빈 threshold.config 보장 (W05 의 학생이 학습 후 채움)
[ -f /etc/suricata/threshold.config ] || touch /etc/suricata/threshold.config

# stats event = 333 field → wazuh JSON_Decoder 의 256 limit 초과 → "Too many fields"
# noise (8초 주기 + alert 가치 없음) 이므로 eve-log 의 types 에서 stats: block 제거.
if grep -q "^        - stats:" /etc/suricata/suricata.yaml; then
    sed -i '/^        - stats:$/,/^            deltas:/d' /etc/suricata/suricata.yaml
    echo "[ips] suricata eve-log: stats event_type disabled (wazuh JSON_Decoder 256 limit)"
fi

# Detect interfaces
PIPE_IFACE=$(ip -o -4 addr show | awk '$4 ~ /^10\.20\.31\./ {print $2; exit}')
DMZ_IFACE=$(ip -o -4 addr show | awk '$4 ~ /^10\.20\.32\./ {print $2; exit}')
echo "[ips] sniff interfaces: pipe=$PIPE_IFACE dmz=$DMZ_IFACE"

mkdir -p /var/log/suricata
# af-packet on both interfaces (forward path is in pipe→dmz, return is dmz→pipe)
suricata -i "$PIPE_IFACE" -i "$DMZ_IFACE" -c /etc/suricata/suricata.yaml \
    --runmode autofp -l /var/log/suricata \
    > /var/log/suricata/stdout.log 2>&1 &

# ─── Wazuh agent ───────────────────────────────────────
if [ -d /var/ossec ]; then
    echo "[ips] configuring Wazuh agent (manager=$WAZUH_MANAGER)"
    sed -i "s|<address>.*</address>|<address>$WAZUH_MANAGER</address>|" /var/ossec/etc/ossec.conf

    if ! grep -q '/var/log/suricata/eve.json' /var/ossec/etc/ossec.conf; then
        sed -i '/<\/ossec_config>/i\
  <localfile>\n    <log_format>json</log_format>\n    <location>/var/log/suricata/eve.json</location>\n  </localfile>\n  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>' /var/ossec/etc/ossec.conf
    fi

    # 6v6-assessor: FIM(suricata 설정/룰 + 실습 디렉터리) + 명령 로깅 localfile (정적·cohort-free, 멱등)
    if ! grep -q '6v6-assessor-collection' /var/ossec/etc/ossec.conf; then
        __fimblk=$(mktemp)
        cat > "$__fimblk" <<'FIMBLK'
  <!-- 6v6-assessor-collection: FIM + cmdlog localfile (정적·cohort-free) -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes" report_changes="yes" whodata="yes">/etc/suricata</directories>
    <directories realtime="yes" report_changes="yes">/home/ccc</directories>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/6v6-cmd.log</location>
  </localfile>
FIMBLK
        __awktmp=$(mktemp)
        awk 'NR==FNR{ins=ins $0 ORS; next} /<\/ossec_config>/ && !d{printf "%s",ins; d=1} {print}' \
            "$__fimblk" /var/ossec/etc/ossec.conf > "$__awktmp" && \
            cat "$__awktmp" > /var/ossec/etc/ossec.conf
        rm -f "$__fimblk" "$__awktmp"
        echo "[ips] ★ Assessor 수집(FIM + cmdlog localfile) 주입"
    fi

    echo "[ips] waiting for Wazuh manager $WAZUH_MANAGER:1515..."
    for i in $(seq 1 30); do
        if (echo > /dev/tcp/$WAZUH_MANAGER/1515) 2>/dev/null; then
            echo "[ips]   manager ready"
            break
        fi
        sleep 2
    done

    /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -A "$(hostname)" 2>&1 | tail -3 || true
    /var/ossec/bin/wazuh-control start 2>&1 | sed 's/^/  /' || true
fi

# ── 6v6 명령 로깅(채점/감사용, cohort-free 정적) ──────────────────────────
: > /var/log/6v6-cmd.log 2>/dev/null || true
chmod 0666 /var/log/6v6-cmd.log 2>/dev/null || true
cat > /etc/profile.d/6v6-cmdlog.sh <<'CMDLOG'
# 6v6: 대화형 셸 명령 로깅(채점/감사). CC/tubewar 가 Assessor command_ran 으로 질의.
case "$-" in *i*) ;; *) return 2>/dev/null ;; esac
__6v6_cmdlog() {
  local rc=$? last
  last=$(history 1 2>/dev/null | sed 's/^ *[0-9]* *//')
  [ -z "$last" ] && return
  local msg="CMD6V6 host=$(hostname) user=${USER:-?} pwd=$PWD rc=$rc cmd=$last"
  logger -p local6.info -t 6v6audit "$msg" 2>/dev/null
  printf '%s %s 6v6audit: %s\n' "$(date '+%b %e %H:%M:%S')" "$(hostname)" "$msg" >> /var/log/6v6-cmd.log 2>/dev/null
}
case ";${PROMPT_COMMAND};" in
  *__6v6_cmdlog*) ;;
  *) PROMPT_COMMAND="__6v6_cmdlog;${PROMPT_COMMAND}" ;;
esac
CMDLOG

# ─── secuops-easy 교육용 GUI: IPS 콘솔 (이미지 내장 → 자동 기동) ──────────────
# 휘발성 docker-exec 주입 대신 entrypoint 에서 영구 기동. down/up·재부팅 후에도
# ips-gui.6v6.lab 가 네트워크/exec 없이 즉시 열린다(HAProxy 라우트는 base config 내장).
if [ -f /opt/suricata_edu_gui/server.py ] && ! pgrep -f /opt/suricata_edu_gui/server.py >/dev/null 2>&1; then
    echo "[ips] starting suricata_edu_gui (IPS 콘솔) on :8080"
    python3 /opt/suricata_edu_gui/server.py 8080 >/var/log/suricata_edu_gui.log 2>&1 &
fi

echo "[ips] starting sshd"
exec /usr/sbin/sshd -D -e
