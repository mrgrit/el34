#!/bin/bash
set -e

SSH_USER="${SSH_USER:-ccc}"
SSH_PASS="${SSH_PASS:-ccc}"
SIEM_HOST="${SIEM_HOST:-10.20.32.100}"
# ★ ':-' 가 아니라 '-' : 미설정이면 fw, 빈 문자열을 명시(attacker-ext, 외부망)하면 그대로 빈값.
DEFAULT_GW="${DEFAULT_GW-10.20.30.1}"

# Default route via fw (so packets to dmz/int go through chain).
# DEFAULT_GW 가 빈값이면(외부망 attacker-ext) docker 기본 GW 유지 — 내부 브리지(ext/dmz/int)에
# 직접 못 닿고 VM 공개 포트로만 접근하는 '진짜 외부 침입자' 모델.
if [ -n "$DEFAULT_GW" ]; then
    echo "[attacker] setting default route via $DEFAULT_GW (fw)"
    ip route del default 2>/dev/null || true
    ip route add default via "$DEFAULT_GW" 2>/dev/null || true
else
    echo "[attacker] DEFAULT_GW 빈값 — docker 기본 라우트 유지(외부망 모델: 공개 포트로만 VM 접근)"
fi

if ! id "$SSH_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo "$SSH_USER"
    echo "${SSH_USER}:${SSH_PASS}" | chpasswd
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$SSH_USER
fi

# ffuf scraper config dir — attack/W07 의 ffuf 가 ~/.config/ffuf/scraper 필요. 사전 생성.
mkdir -p /home/$SSH_USER/.config/ffuf/scraper
chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.config

# bastion 의 pubkey 을 /keys (호스트 RO mount) → ccc 의 authorized_keys 배포. bastion 의
# ProxyJump ssh 가 password 없이 통과. 학생 환경마다 다른 키 (gitignore).
if [ -f /keys/id_rsa.pub ]; then
    mkdir -p /home/$SSH_USER/.ssh
    cat /keys/id_rsa.pub > /home/$SSH_USER/.ssh/authorized_keys
    chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh
    chmod 700 /home/$SSH_USER/.ssh
    chmod 600 /home/$SSH_USER/.ssh/authorized_keys
    echo "[attacker] authorized_keys deployed — bastion 의 password-less ssh 가능"
fi

sed -i 's|^#PrintMotd.*|PrintMotd yes|' /etc/ssh/sshd_config
echo "cat /etc/motd 2>/dev/null" >> /home/$SSH_USER/.bashrc

# metasploit-framework — msfinstall 이 /opt/metasploit-framework 에 설치 하지만
# /usr/local/bin/ 의 wrapper symlink 가 누락되어 `which msfconsole` fail. PATH 의
# 학생 lab 의 W01 S1 (13 도구 매트릭스) 통과 위해 symlink 생성.
if [ -d /opt/metasploit-framework/bin ]; then
    for b in msfconsole msfvenom msfdb msfd msfrpc msfrpcd msfupdate; do
        if [ -f "/opt/metasploit-framework/bin/$b" ] && [ ! -e "/usr/local/bin/$b" ]; then
            ln -sf "/opt/metasploit-framework/bin/$b" "/usr/local/bin/$b"
        fi
    done
    echo "[attacker] msf wrappers symlinked to /usr/local/bin/"
fi

echo "[attacker] configuring rsyslog forward -> $SIEM_HOST:514/udp"
cat > /etc/rsyslog.d/50-forward-siem.conf <<RSYSLOG
# 6v6: attacker -> siem syslog forward (syslog paradigm vs Wazuh agent)
*.*  @${SIEM_HOST}:514
RSYSLOG
service rsyslog restart 2>/dev/null || service rsyslog start 2>/dev/null || true

sed -i 's|^#SyslogFacility.*|SyslogFacility AUTH|' /etc/ssh/sshd_config
sed -i 's|^#LogLevel.*|LogLevel INFO|' /etc/ssh/sshd_config

# SSH host key 영구화 — fresh 재배포 시 학생 PC known_hosts mismatch 방지.
# (attacker-ssh-host volume 에 보존 → 컨테이너 재생성해도 같은 host key 유지)
SSH_HOST_KEY_DIR=/var/lib/ssh-host-keys
mkdir -p "$SSH_HOST_KEY_DIR"
for t in rsa ecdsa ed25519; do
    if [ ! -f "$SSH_HOST_KEY_DIR/ssh_host_${t}_key" ]; then
        ssh-keygen -q -t "$t" -f "$SSH_HOST_KEY_DIR/ssh_host_${t}_key" -N "" -C "attacker-$t"
        echo "[attacker] ssh host key 생성: $t (영구 보존)"
    fi
    chmod 600 "$SSH_HOST_KEY_DIR/ssh_host_${t}_key"
done
sed -i '/^HostKey \/var\/lib\/ssh-host-keys/d' /etc/ssh/sshd_config
{
    echo ""
    echo "# ── 영구 host key (attacker-ssh-host volume) ──"
    for t in rsa ecdsa ed25519; do
        echo "HostKey $SSH_HOST_KEY_DIR/ssh_host_${t}_key"
    done
} >> /etc/ssh/sshd_config

# SubAgent (Manager A2A worker on :8002)
if [ -f /opt/subagent.py ]; then
    echo "[attacker] starting SubAgent on :8002"
    CCC_ROLE=attacker nohup python3 /opt/subagent.py > /var/log/subagent.log 2>&1 < /dev/null &
fi

# ── 6v6 명령 로깅(채점/감사용, cohort-free 정적) ──────────────────────────
# attacker 는 Wazuh agent 없음 → local6 가 기존 rsyslog(*.* @siem:514) 로 manager 전달.
# 컨테이너에서 service rsyslog 가 데몬을 유지 못 하는 경우가 있어 미기동 시 직접 보장.
pgrep -x rsyslogd >/dev/null 2>&1 || rsyslogd 2>/dev/null || true
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

echo "[attacker] starting sshd"
exec /usr/sbin/sshd -D -e
