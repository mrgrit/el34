#!/bin/bash
set -e

SSH_USER="${SSH_USER:-ccc}"
SSH_PASS="${SSH_PASS:-ccc}"
WAZUH_MANAGER="${WAZUH_MANAGER:-10.20.32.100}"
IPS_PIPE_IP="${IPS_PIPE_IP:-10.20.31.2}"

if ! id "$SSH_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo "$SSH_USER"
    echo "${SSH_USER}:${SSH_PASS}" | chpasswd
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$SSH_USER
fi

# bastion pubkey → ccc authorized_keys (ProxyJump 의 첫 hop). 학생 환경마다 다른 키.
if [ -f /keys/id_rsa.pub ]; then
    mkdir -p /home/$SSH_USER/.ssh
    cat /keys/id_rsa.pub > /home/$SSH_USER/.ssh/authorized_keys
    chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh
    chmod 700 /home/$SSH_USER/.ssh
    chmod 600 /home/$SSH_USER/.ssh/authorized_keys
    echo "[fw] authorized_keys deployed — bastion 의 password-less ssh 가능"
fi

# ─── Routing: dmz/int 은 ips 경유 ───────────────────────
echo "[fw] adding routes (dmz/int via ips $IPS_PIPE_IP)"
ip route add 10.20.32.0/24 via "$IPS_PIPE_IP" 2>/dev/null || true
ip route add 10.20.40.0/24 via "$IPS_PIPE_IP" 2>/dev/null || true

# ─── nftables ─────────────────────────────────────────
echo "[fw] applying nftables (six_filter / six_nat tables)"
nft -f /etc/nftables.conf 2>&1 | sed 's/^/  /' || echo "[fw] WARN: nft apply failed"

# ─── L3 포트분기 DNAT (HAProxy 제거 — L7 종료 안 함, 출처 IP 보존) ─────────
# 호스트 .161 publish → fw → (DNAT) → web(ModSec/WAF) → app.  masquerade 안 함:
# 출처(.202)가 web 까지 그대로 도달 → WAF 가 진짜 공격자를 로깅/차단.
# 리턴: web→ips→fw→host(conntrack 역추적)→.202  (ips default GW=fw 로 보장).
WEB_DMZ_IP="${WEB_DMZ_IP:-10.20.32.80}"
BASTION_API_IP="${BASTION_API_IP:-10.20.30.201}"
echo "[fw] installing port-split DNAT → web ($WEB_DMZ_IP)"
# 80/443: Host 헤더 vhost (web/Apache 분기).  8001-8007: 사이트별 포트분기.
nft add rule ip six_nat prerouting tcp dport 80  dnat to ${WEB_DMZ_IP}:80   2>/dev/null || true
nft add rule ip six_nat prerouting tcp dport 443 dnat to ${WEB_DMZ_IP}:443  2>/dev/null || true
for p in 8001 8002 8003 8004 8005 8006 8007; do
    nft add rule ip six_nat prerouting tcp dport $p dnat to ${WEB_DMZ_IP}:$p 2>/dev/null || true
done
# bastion API (관리) — ext 망 bastion 으로
nft add rule ip six_nat prerouting tcp dport 9100 dnat to ${BASTION_API_IP}:9100 2>/dev/null || true

# ─── Wazuh agent ────────────────────────────────────────
if [ -d /var/ossec ]; then
    echo "[fw] configuring Wazuh agent (manager=$WAZUH_MANAGER)"
    sed -i "s|<address>.*</address>|<address>$WAZUH_MANAGER</address>|" /var/ossec/etc/ossec.conf

    if ! grep -q '/var/log/syslog' /var/ossec/etc/ossec.conf; then
        sed -i '/<\/ossec_config>/i\
  <localfile>\n    <log_format>syslog</log_format>\n    <location>/var/log/syslog</location>\n  </localfile>' /var/ossec/etc/ossec.conf
    fi

    # el34-assessor: FIM(nftables/haproxy/실습 디렉터리) + 명령 로깅 localfile (정적·cohort-free, 멱등)
    if ! grep -q 'el34-assessor-collection' /var/ossec/etc/ossec.conf; then
        __fimblk=$(mktemp)
        cat > "$__fimblk" <<'FIMBLK'
  <!-- el34-assessor-collection: FIM + cmdlog localfile (정적·cohort-free) -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>300</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories realtime="yes" report_changes="yes" whodata="yes">/etc/nftables.conf</directories>
    <directories realtime="yes" report_changes="yes" whodata="yes">/etc/haproxy</directories>
    <directories realtime="yes" report_changes="yes">/home/ccc</directories>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/el34-cmd.log</location>
  </localfile>
FIMBLK
        __awktmp=$(mktemp)
        awk 'NR==FNR{ins=ins $0 ORS; next} /<\/ossec_config>/ && !d{printf "%s",ins; d=1} {print}' \
            "$__fimblk" /var/ossec/etc/ossec.conf > "$__awktmp" && \
            cat "$__awktmp" > /var/ossec/etc/ossec.conf
        rm -f "$__fimblk" "$__awktmp"
        echo "[fw] ★ Assessor 수집(FIM + cmdlog localfile) 주입"
    fi

    echo "[fw] waiting for Wazuh manager $WAZUH_MANAGER:1515..."
    for i in $(seq 1 30); do
        if (echo > /dev/tcp/$WAZUH_MANAGER/1515) 2>/dev/null; then
            echo "[fw]   manager ready"
            break
        fi
        sleep 2
    done

    /var/ossec/bin/agent-auth -m "$WAZUH_MANAGER" -A "$(hostname)" 2>&1 | tail -3 || true
    /var/ossec/bin/wazuh-control start 2>&1 | sed 's/^/  /' || true
fi

# ── el34 명령 로깅(채점/감사용, cohort-free 정적) ──────────────────────────
: > /var/log/el34-cmd.log 2>/dev/null || true
chmod 0666 /var/log/el34-cmd.log 2>/dev/null || true
cat > /etc/profile.d/el34-cmdlog.sh <<'CMDLOG'
# el34: 대화형 셸 명령 로깅(채점/감사). CC/tubewar 가 Assessor command_ran 으로 질의.
case "$-" in *i*) ;; *) return 2>/dev/null ;; esac
__el34_cmdlog() {
  local rc=$? last
  last=$(history 1 2>/dev/null | sed 's/^ *[0-9]* *//')
  [ -z "$last" ] && return
  local msg="CMDEL34 host=$(hostname) user=${USER:-?} pwd=$PWD rc=$rc cmd=$last"
  logger -p local6.info -t el34audit "$msg" 2>/dev/null
  printf '%s %s el34audit: %s\n' "$(date '+%b %e %H:%M:%S')" "$(hostname)" "$msg" >> /var/log/el34-cmd.log 2>/dev/null
}
case ";${PROMPT_COMMAND};" in
  *__el34_cmdlog*) ;;
  *) PROMPT_COMMAND="__el34_cmdlog;${PROMPT_COMMAND}" ;;
esac
CMDLOG

# ─── secuops-easy 교육용 GUI: 방화벽 콘솔 (이미지 내장 → 자동 기동) ──────────
# 휘발성 docker-exec 주입 대신 entrypoint 에서 영구 기동. down/up·재부팅 후에도
# fw-gui.el34.lab 가 네트워크/exec 없이 즉시 열린다(HAProxy 라우트는 base config 내장).
if [ -f /opt/nft_edu_gui/server.py ] && ! pgrep -f /opt/nft_edu_gui/server.py >/dev/null 2>&1; then
    echo "[fw] starting nft_edu_gui (방화벽 콘솔) on :8080"
    python3 /opt/nft_edu_gui/server.py 8080 >/var/log/nft_edu_gui.log 2>&1 &
fi

echo "[fw] starting sshd"
exec /usr/sbin/sshd -D -e
