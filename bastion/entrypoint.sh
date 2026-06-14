#!/bin/bash
set -e

SSH_USER="${SSH_USER:-ccc}"
SSH_PASS="${SSH_PASS:-ccc}"
SIEM_HOST="${SIEM_HOST:-10.20.32.100}"
DEFAULT_GW="${DEFAULT_GW:-10.20.30.1}"

# Default route via fw (so packets to dmz/int go through chain)
echo "[bastion] setting default route via $DEFAULT_GW (fw)"
ip route del default 2>/dev/null || true
ip route add default via "$DEFAULT_GW" 2>/dev/null || true

# ─── EG seed import — P24 266 mission 학습된 KG (graph 397 node, anchor 168, audit 327) ──
# 컨테이너 첫 시작 시 (DB 미존재) seed 적용. 학생 환경 보존: 이미 KG 있으면 skip.
EG_DATA_DIR=/opt/ccc-src/data
EG_SEED_DIR=/opt/ccc-src/data/seed
mkdir -p "$EG_DATA_DIR"
if [ -f "$EG_SEED_DIR/bastion_graph_seed.db" ] && [ ! -f "$EG_DATA_DIR/bastion_graph.db" ]; then
    cp "$EG_SEED_DIR/bastion_graph_seed.db" "$EG_DATA_DIR/bastion_graph.db"
    echo "[bastion] ★ EG seed: bastion_graph.db 적용 (P24 266 mission 학습)"
fi
if [ -f "$EG_SEED_DIR/bastion_audit_seed.db" ] && [ ! -f "$EG_DATA_DIR/bastion_audit.db" ]; then
    cp "$EG_SEED_DIR/bastion_audit_seed.db" "$EG_DATA_DIR/bastion_audit.db"
    echo "[bastion] ★ EG seed: bastion_audit.db 적용"
fi

if ! id "$SSH_USER" >/dev/null 2>&1; then
    useradd -m -s /bin/bash -G sudo "$SSH_USER"
    echo "${SSH_USER}:${SSH_PASS}" | chpasswd
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$SSH_USER
fi

# secuops/W08-S1 의 'docker ps' 학생 명령 위해 ccc 를 docker group 에 추가.
# /var/run/docker.sock 의 GID 와 일치하는 group 생성 + ccc 추가.
if [ -S /var/run/docker.sock ]; then
    DOCKER_GID=$(stat -c %g /var/run/docker.sock)
    if ! getent group docker >/dev/null 2>&1; then
        groupadd -g "$DOCKER_GID" docker 2>/dev/null || true
    else
        groupmod -g "$DOCKER_GID" docker 2>/dev/null || true
    fi
    usermod -aG docker "$SSH_USER" 2>/dev/null || true
    echo "[bastion] ccc → docker group (GID=$DOCKER_GID) — secuops W08 의 docker ps 가능"
fi

# ~/.ssh/config — ProxyJump aliases
mkdir -p /home/$SSH_USER/.ssh
cat > /home/$SSH_USER/.ssh/config <<SSHCFG
# 4-tier chained topology — direct/jump aliases
Host 6v6-fw fw
    HostName 10.20.30.1
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

Host 6v6-attacker attacker
    HostName 10.20.30.202
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

# pipe/dmz/int reachable via fw (route forwarding is in place)
Host 6v6-ips ips
    HostName 10.20.31.2
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ProxyJump 6v6-fw

Host 6v6-web web
    HostName 10.20.32.80
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ProxyJump 6v6-fw

Host 6v6-portal portal
    HostName 10.20.32.50
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ProxyJump 6v6-fw

Host 6v6-siem siem
    HostName 10.20.32.100
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    ProxyJump 6v6-fw

# W11 학습용 — sysmon-host (ext network, systemd 컨테이너)
Host 6v6-sysmon-host sysmon-host
    HostName 10.20.30.210
    User $SSH_USER
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null

# Wazuh Dashboard (https UI, no SSH): https://siem.6v6.lab/
#   admin / SecretPassword
SSHCFG
chmod 600 /home/$SSH_USER/.ssh/config
chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh

# /keys (호스트 ./keys bind mount, RO) → ccc 의 id_rsa + authorized_keys 배포. bastion
# 은 양쪽 모두 보유 (id_rsa = ProxyJump client key, authorized_keys = bastion 자체 로그인).
# 학생 신규 배포 시 6v6.sh 가 ssh-keygen 자동 생성하여 /keys 채움.
if [ -f /keys/id_rsa ] && [ -f /keys/id_rsa.pub ]; then
    cp /keys/id_rsa     /home/$SSH_USER/.ssh/id_rsa
    cp /keys/id_rsa.pub /home/$SSH_USER/.ssh/id_rsa.pub
    cat /keys/id_rsa.pub > /home/$SSH_USER/.ssh/authorized_keys
    chown -R $SSH_USER:$SSH_USER /home/$SSH_USER/.ssh
    chmod 600 /home/$SSH_USER/.ssh/id_rsa /home/$SSH_USER/.ssh/authorized_keys
    chmod 644 /home/$SSH_USER/.ssh/id_rsa.pub
    echo "[bastion] SSH key deployed (id_rsa + authorized_keys) — password-less ssh 6v6-fw 가능"
else
    echo "[bastion] WARN: /keys/id_rsa 없음 — 6v6.sh up 의 ensure_ssh_keys 실행 안 됨? password ssh 로 fallback."
fi

cat > /etc/motd <<MOTD
========================================================
  6v6 Bastion - single entry point for the lab
========================================================
ProxyJump aliases: ssh secu | ssh web | ssh attacker
SIEM via ssh 6v6-siem (ProxyJump fw) or Wazuh dashboard https://siem.6v6.lab/
API: http://localhost:9100/health
========================================================
MOTD

# rsyslog forward (syslog paradigm) - bastion auth/system -> siem:514/udp
echo "[bastion] configuring rsyslog forward -> $SIEM_HOST:514/udp"
cat > /etc/rsyslog.d/50-forward-siem.conf <<RSYSLOG
# 6v6: bastion -> siem syslog forward (syslog paradigm vs Wazuh agent)
*.*  @${SIEM_HOST}:514
RSYSLOG

# ── Bastion audit log → wazuh (local5 facility, separate tag 'bastion-audit') ──
# audit.py 가 logging.handlers.SysLogHandler(LOG_LOCAL5) 로 송신.
# wazuh decoder (local_decoder.xml) 가 "bastion-audit {json}" 패턴 parse.
cat > /etc/rsyslog.d/51-bastion-audit.conf <<RSYSLOG_AUDIT
# Bastion audit log → siem (wazuh) — local5 facility 만 별도 forward
local5.*  @${SIEM_HOST}:514
# 동시에 로컬 파일에도 저장 (디버그 + Wazuh agent 가 파일 watch 가능)
local5.*  /var/log/bastion-audit.log
RSYSLOG_AUDIT
touch /var/log/bastion-audit.log
chmod 644 /var/log/bastion-audit.log

service rsyslog restart 2>/dev/null || service rsyslog start 2>/dev/null || true

echo "[bastion] starting Bastion API on :9100"
# Full CCC bastion (apps.bastion.api) 가 import 가능 + LLM_BASE_URL 설정 시 활성.
# 아니면 minimal stub (/opt/bastion-api/api.py) 로 fallback.
if [ -d /opt/ccc-src/apps/bastion ] && [ -n "${LLM_BASE_URL:-}" ]; then
    : "${LLM_MANAGER_MODEL:=gemma3:4b}"
    : "${LLM_SUBAGENT_MODEL:=gemma3:4b}"
    # packages/ 가 sys.path 에 있어야 `from bastion.X` import 가능 (CCC namespace 규약)
    export LLM_BASE_URL LLM_MANAGER_MODEL LLM_SUBAGENT_MODEL \
           PYTHONPATH=/opt/ccc-src:/opt/ccc-src/packages
    echo "[bastion] Full Bastion (apps.bastion.api) — LLM=$LLM_BASE_URL model=$LLM_MANAGER_MODEL"
    cd /opt/ccc-src && \
        python3 -m uvicorn apps.bastion.api:app --host 0.0.0.0 --port 9100 \
            > /var/log/bastion-api.log 2>&1 &
else
    echo "[bastion] Stub Bastion (/health only) — LLM_BASE_URL 미설정 시 fallback"
    cd /opt/bastion-api && \
        python3 -m uvicorn api:app --host 0.0.0.0 --port 9100 \
            > /var/log/bastion-api.log 2>&1 &
fi

# sshd auth events -> syslog
sed -i 's|^#SyslogFacility.*|SyslogFacility AUTH|' /etc/ssh/sshd_config
sed -i 's|^#LogLevel.*|LogLevel INFO|' /etc/ssh/sshd_config

# SSH host key 영구화 — fresh 재배포 시 학생 PC known_hosts mismatch 방지.
# (bastion-ssh-host volume 에 보존 → 컨테이너 재생성해도 같은 host key 유지)
SSH_HOST_KEY_DIR=/var/lib/bastion/ssh-host-keys
mkdir -p "$SSH_HOST_KEY_DIR"
for t in rsa ecdsa ed25519; do
    if [ ! -f "$SSH_HOST_KEY_DIR/ssh_host_${t}_key" ]; then
        ssh-keygen -q -t "$t" -f "$SSH_HOST_KEY_DIR/ssh_host_${t}_key" -N "" -C "bastion-$t"
        echo "[bastion] ssh host key 생성: $t (영구 보존)"
    fi
    chmod 600 "$SSH_HOST_KEY_DIR/ssh_host_${t}_key"
done
# sshd_config 의 HostKey directive 를 volume 경로로 override
sed -i '/^HostKey \/var\/lib\/bastion/d' /etc/ssh/sshd_config
{
    echo ""
    echo "# ── 영구 host key (bastion-ssh-host volume) ──"
    for t in rsa ecdsa ed25519; do
        echo "HostKey $SSH_HOST_KEY_DIR/ssh_host_${t}_key"
    done
} >> /etc/ssh/sshd_config

# ── 6v6 명령 로깅(채점/감사용, cohort-free 정적) ──────────────────────────
# Bastion 의 두뇌(KG/Manager/SubAgent)·API(/health /exec /chat)·ProxyJump 와 무관한
# 셸 profile.d 드롭인일 뿐 — 기존 역할 무변경. local6 는 기존 rsyslog(*.* @siem:514) 경유.
# 컨테이너에서 rsyslog 데몬이 안 떠 있는 경우가 있어 미기동 시 직접 보장(전송 경로 확보).
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

echo "[bastion] starting sshd"
exec /usr/sbin/sshd -D -e
