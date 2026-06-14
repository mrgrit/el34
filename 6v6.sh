#!/usr/bin/env bash
# 6v6 — CCC infra docker single-VM operations script
set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

ensure_env() {
    [ -f .env ] || { echo "[6v6] .env not found -> 'cp .env.example .env' (auto)"; cp .env.example .env; }
}

ensure_ssh_keys() {
    # 학생 신규 배포 — keys/ 디렉토리 + bastion SSH key 자동 생성. bind mount 로 6
    # 컨테이너 (bastion / attacker / fw / ips / web / siem) 가 /keys read-only 마운트.
    # bastion 의 ccc 가 id_rsa 보유, 나머지가 id_rsa.pub 을 authorized_keys 로 받아
    # password 없이 ssh 6v6-fw 등 ProxyJump 가능. 학생 환경마다 다른 키 생성 (gitignore).
    mkdir -p keys
    if [ ! -f keys/id_rsa ]; then
        if ! command -v ssh-keygen >/dev/null 2>&1; then
            echo "[6v6] ssh-keygen not found. Install with 'sudo apt install -y openssh-client' and re-run."
            exit 1
        fi
        ssh-keygen -t ed25519 -f keys/id_rsa -N "" -C "6v6-bastion@auto" >/dev/null 2>&1
        echo "[6v6] generated SSH key pair (keys/id_rsa) - for password-less SSH between containers"
    fi
    chmod 600 keys/id_rsa  2>/dev/null || true
    chmod 644 keys/id_rsa.pub 2>/dev/null || true
}

ensure_misp_env() {
    # secuops/W14 (MISP) 의 학생 신규 배포. .env.misp 가 없으면 template + 학생 환경 값 자동.
    [ -f .env.misp ] && return 0
    [ -f .env.misp.example ] || return 0
    cp .env.misp.example .env.misp
    VM_IP=$(vm_ip 2>/dev/null || echo "127.0.0.1")
    # MISP port 8880/8443 (6v6 의 fw HAProxy 가 80/443 점유 → 충돌 회피)
    sed -i "s|^BASE_URL=.*|BASE_URL=https://${VM_IP}:8443|" .env.misp
    sed -i "s|^MYSQL_PASSWORD=.*|MYSQL_PASSWORD=$(openssl rand -hex 16)|" .env.misp
    sed -i "s|^MYSQL_ROOT_PASSWORD=.*|MYSQL_ROOT_PASSWORD=$(openssl rand -hex 16)|" .env.misp
    sed -i "s|^DISABLE_IPV6=.*|DISABLE_IPV6=true|" .env.misp
    sed -i "s|^# CORE_HTTP_PORT=.*|CORE_HTTP_PORT=8880|; s|^CORE_HTTP_PORT=$|CORE_HTTP_PORT=8880|" .env.misp
    sed -i "s|^# CORE_HTTPS_PORT=.*|CORE_HTTPS_PORT=8443|; s|^CORE_HTTPS_PORT=$|CORE_HTTPS_PORT=8443|" .env.misp
    # default 값으로 추가 (sed가 못 잡으면)
    grep -q "^CORE_HTTP_PORT=" .env.misp || echo "CORE_HTTP_PORT=8880" >> .env.misp
    grep -q "^CORE_HTTPS_PORT=" .env.misp || echo "CORE_HTTPS_PORT=8443" >> .env.misp
    chmod 600 .env.misp
    echo "[6v6] generated .env.misp - MISP 5 container stack (core/db/redis/modules/mail)"
}

ensure_opencti_env() {
    # secuops/W12-W13 (OpenCTI) 의 학생 신규 배포 자동화. .env.opencti 가 없으면 자동 생성.
    # docker-compose.opencti.yml 의 모든 ${OPENCTI_*} / ${MINIO_*} / ${RABBITMQ_*} env 채움.
    [ -f .env.opencti ] && return 0
    if ! command -v openssl >/dev/null 2>&1 || ! command -v uuidgen >/dev/null 2>&1; then
        echo "[6v6] WARN: openssl/uuidgen not installed - OpenCTI overlay auto-gen unavailable."
        echo "      Install with 'sudo apt install -y openssl uuid-runtime' and re-run 'bash 6v6.sh up'."
        return 1
    fi
    VM_IP=$(vm_ip 2>/dev/null || echo "127.0.0.1")
    cat > .env.opencti <<ENV
# OpenCTI 7.x — 학생 신규 배포 자동 생성. 환경마다 다른 UUID/key (재현 금지).
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=ChangeMe123!
OPENCTI_ADMIN_TOKEN=$(uuidgen)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(uuidgen)
OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)
OPENCTI_BASE_URL=http://${VM_IP}:8080
OPENCTI_EXTERNAL_SCHEME=http
OPENCTI_HOST=${VM_IP}
OPENCTI_PORT=8080
MINIO_ROOT_USER=$(uuidgen)
MINIO_ROOT_PASSWORD=$(uuidgen)
RABBITMQ_DEFAULT_USER=opencti
RABBITMQ_DEFAULT_PASS=$(uuidgen)
ELASTIC_MEMORY_SIZE=1G
CONNECTOR_HISTORY_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_STIX_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_CSV_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_TXT_ID=$(uuidgen)
CONNECTOR_EXPORT_FILE_XLSX_ID=$(uuidgen)
CONNECTOR_IMPORT_FILE_STIX_ID=$(uuidgen)
CONNECTOR_IMPORT_FILE_YARA_ID=$(uuidgen)
CONNECTOR_IMPORT_FILE_PDF_OBSERVABLES_ID=$(uuidgen)
CONNECTOR_ANALYSIS_ID=$(uuidgen)
CONNECTOR_IMPORT_DOCUMENT_ID=$(uuidgen)
CONNECTOR_IMPORT_EXTERNAL_REFERENCE_ID=$(uuidgen)
CONNECTOR_MITRE_ID=$(uuidgen)
CONNECTOR_OPENCTI_ID=$(uuidgen)
SMTP_HOSTNAME=localhost
ENV
    chmod 600 .env.opencti
    echo "[6v6] generated .env.opencti - OpenCTI 7.x ENCRYPTION_KEY + TOKEN + MINIO + RABBITMQ"
}

vm_ip() {
    # VM external IP (for student-facing instructions)
    ip -4 -o addr show 2>/dev/null \
        | awk '{print $4}' \
        | grep -E '^(192\.168|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
        | grep -v '^10\.20\.30\.' \
        | head -1 \
        | cut -d/ -f1
}

cmd_install() {
    # Auto-install docker + compose + helpers on a fresh Debian/Ubuntu VM.
    if ! command -v sudo >/dev/null 2>&1; then
        echo "[6v6] sudo is required. Install with 'apt install sudo' first."
        exit 1
    fi
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "[6v6] Auto-install supports Debian/Ubuntu only."
        echo "      For RHEL/Arch/etc, install docker-ce + docker-compose-plugin manually,"
        echo "      then run 'bash 6v6.sh up'."
        exit 1
    fi

    echo "[6v6] (1/4) apt-get update"
    sudo apt-get update -qq

    echo "[6v6] (2/4) install helpers (git, curl, jq, sshpass, net-tools, iproute2, dnsutils, python3-venv)"
    sudo apt-get install -y --no-install-recommends \
        ca-certificates curl gnupg lsb-release \
        git jq sshpass net-tools iproute2 dnsutils \
        python3-venv python3-pip >/dev/null

    if ! command -v docker >/dev/null 2>&1; then
        echo "[6v6] (3/4) install Docker Engine"
        local OS_ID OS_CODE
        OS_ID=$(. /etc/os-release && echo "$ID")
        OS_CODE=$(. /etc/os-release && echo "$VERSION_CODENAME")
        case "$OS_ID" in
            ubuntu|debian) ;;
            *) echo "[6v6] unsupported distro: $OS_ID — Ubuntu 22.04 or Debian 12 recommended"; exit 1 ;;
        esac

        sudo install -m 0755 -d /etc/apt/keyrings
        sudo curl -fsSL "https://download.docker.com/linux/$OS_ID/gpg" -o /etc/apt/keyrings/docker.asc
        sudo chmod a+r /etc/apt/keyrings/docker.asc

        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$OS_ID $OS_CODE stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

        sudo apt-get update -qq
        sudo apt-get install -y --no-install-recommends \
            docker-ce docker-ce-cli containerd.io \
            docker-buildx-plugin docker-compose-plugin

        sudo systemctl enable --now docker
        sudo usermod -aG docker "$USER"
        echo "[6v6]   Docker Engine installed: $(docker --version)"
    else
        echo "[6v6] (3/4) Docker already installed: $(docker --version)"
    fi

    if ! docker compose version >/dev/null 2>&1; then
        echo "[6v6]   docker compose plugin missing — installing"
        sudo apt-get install -y --no-install-recommends docker-compose-plugin
    fi

    # Configure Docker daemon DNS - prevents "network is unreachable" pull errors
    # on VMs where /etc/resolv.conf points to a DNS that doesn't resolve docker.io.
    if [ ! -f /etc/docker/daemon.json ] || ! grep -q '"dns"' /etc/docker/daemon.json 2>/dev/null; then
        echo "[6v6] (3.5/4) configure Docker daemon DNS (8.8.8.8, 1.1.1.1)"
        sudo mkdir -p /etc/docker
        if [ -f /etc/docker/daemon.json ]; then
            sudo cp /etc/docker/daemon.json /etc/docker/daemon.json.bak.$(date +%s)
            # Merge dns into existing JSON (best-effort with jq, fallback to overwrite)
            if command -v jq >/dev/null 2>&1; then
                sudo jq '. + {"dns":["8.8.8.8","1.1.1.1"]}' /etc/docker/daemon.json | \
                    sudo tee /etc/docker/daemon.json.new >/dev/null && \
                    sudo mv /etc/docker/daemon.json.new /etc/docker/daemon.json
            else
                echo '{"dns":["8.8.8.8","1.1.1.1"]}' | sudo tee /etc/docker/daemon.json >/dev/null
            fi
        else
            echo '{"dns":["8.8.8.8","1.1.1.1"]}' | sudo tee /etc/docker/daemon.json >/dev/null
        fi
        sudo systemctl restart docker 2>/dev/null || true
    fi

    echo "[6v6] (4/4) verify"
    echo "  - docker:         $(docker --version 2>/dev/null || echo MISSING)"
    echo "  - docker compose: $(docker compose version 2>/dev/null | head -1 || echo MISSING)"
    echo "  - git:            $(git --version 2>/dev/null || echo MISSING)"
    echo "  - jq:             $(jq --version 2>/dev/null || echo MISSING)"

    if ! id -nG "$USER" 2>/dev/null | grep -qw docker; then
        echo
        echo "[6v6] * 'docker' group membership is not active in this shell."
        echo "      -> Open a NEW terminal, OR run 'newgrp docker' in this shell,"
        echo "      -> then 'bash 6v6.sh up' to start."
        exit 0
    fi

    echo
    echo "[6v6] install complete — run 'bash 6v6.sh up' to start the 6v6 environment."
}

cmd_check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "[6v6] X Docker is not installed."
        echo "      -> Run 'bash 6v6.sh install' for auto-setup, or install manually."
        exit 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "[6v6] X Cannot reach Docker daemon."
        echo "      -> Run with sudo, or:"
        echo "         sudo usermod -aG docker \$USER && newgrp docker"
        exit 1
    fi
    if ! docker compose version >/dev/null 2>&1; then
        echo "[6v6] X 'docker compose' plugin missing."
        echo "      -> Run 'bash 6v6.sh install' to add it."
        exit 1
    fi
}

cmd_check_network() {
    # Verify outbound connectivity + DNS works for Docker Hub / GitHub.
    # Without this, `docker compose up` fails mid-pull with confusing errors like
    # "failed to copy: failed to do request: ... network is unreachable".
    local fail=0
    if ! getent hosts registry-1.docker.io >/dev/null 2>&1; then
        echo "[6v6] X DNS cannot resolve 'registry-1.docker.io'."
        echo "      Fix:  echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf"
        echo "      or check /etc/systemd/resolved.conf and 'systemctl restart systemd-resolved'."
        fail=1
    fi
    if ! curl -s -o /dev/null -w "%{http_code}" --max-time 8 https://registry-1.docker.io/v2/ 2>/dev/null | grep -qE '^(200|401)$'; then
        echo "[6v6] X Cannot reach https://registry-1.docker.io (Docker Hub)."
        echo "      Check VM network: VMware NAT mode + host has internet,"
        echo "      or corporate proxy: configure /etc/systemd/system/docker.service.d/http-proxy.conf"
        fail=1
    fi
    if ! getent hosts github.com >/dev/null 2>&1; then
        echo "[6v6] X DNS cannot resolve 'github.com' (secuops-easy GUI repos)."
        fail=1
    fi
    if [ "$fail" = "1" ]; then
        echo "[6v6] Network preflight failed - fix above and re-run 'bash 6v6.sh up'."
        exit 1
    fi
}

cmd_check_kernel() {
    # wazuh-indexer (OpenSearch) requires vm.max_map_count >= 262144
    local cur
    cur=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
    if [ "$cur" -lt 262144 ]; then
        echo "[6v6] tuning vm.max_map_count for wazuh-indexer (OpenSearch)"
        if sudo -n true 2>/dev/null; then
            sudo sysctl -w vm.max_map_count=262144 >/dev/null
            grep -q '^vm.max_map_count' /etc/sysctl.conf 2>/dev/null || \
                echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf >/dev/null
        else
            echo "[6v6]   sudo unavailable; please run manually:"
            echo "         sudo sysctl -w vm.max_map_count=262144"
            echo "         echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf"
        fi
    fi

    # bridge-nf-call=0 — required for inter-bridge forwarding (fw->ips->web).
    # When br_netfilter is loaded with bridge-nf-call=1, host iptables FORWARD
    # processes packets traversing docker bridges, and docker's per-IP DROP
    # rules block our 4-tier chain.
    if sudo -n true 2>/dev/null; then
        sudo modprobe br_netfilter 2>/dev/null || true
        if [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ]; then
            sudo sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1
            grep -q 'bridge-nf-call-iptables' /etc/sysctl.conf 2>/dev/null || \
                echo 'net.bridge.bridge-nf-call-iptables=0' | sudo tee -a /etc/sysctl.conf >/dev/null
        fi
    fi
}

cmd_setup_forward() {
    # Docker's DOCKER-INTERNAL chain drops packets between containers on
    # different bridges by default. For our 4-tier chain (fw->ips->web->vuln)
    # to work, we must allow forwarding between our bridges in DOCKER-USER.
    if ! command -v sudo >/dev/null 2>&1; then
        echo "[6v6] WARN: sudo unavailable — cannot configure inter-bridge forwarding"
        return
    fi

    local ext_br pipe_br dmz_br int_br
    ext_br=$(docker network inspect 6v6-ext  -f '{{range $k,$v := .Options}}{{if eq $k "com.docker.network.bridge.name"}}{{$v}}{{end}}{{end}}' 2>/dev/null)
    [ -z "$ext_br" ]  && ext_br=$(docker network inspect 6v6-ext  -f '{{.Id}}' 2>/dev/null | cut -c1-12 | sed 's/^/br-/')
    pipe_br=$(docker network inspect 6v6-pipe -f '{{.Id}}' 2>/dev/null | cut -c1-12 | sed 's/^/br-/')
    dmz_br=$(docker network inspect 6v6-dmz  -f '{{.Id}}' 2>/dev/null | cut -c1-12 | sed 's/^/br-/')
    int_br=$(docker network inspect 6v6-int  -f '{{.Id}}' 2>/dev/null | cut -c1-12 | sed 's/^/br-/')

    if [ -z "$pipe_br" ] || [ -z "$dmz_br" ]; then
        echo "[6v6] WARN: cannot detect 6v6 bridge interfaces — networks created?"
        return
    fi

    echo "[6v6] inserting DOCKER-USER forward rules (ext<->pipe<->dmz<->int)"
    echo "      ext=$ext_br  pipe=$pipe_br  dmz=$dmz_br  int=$int_br"
    sudo iptables -F DOCKER-USER 2>/dev/null || true
    for pair in \
        "$ext_br $pipe_br" "$pipe_br $ext_br" \
        "$pipe_br $dmz_br" "$dmz_br $pipe_br" \
        "$dmz_br $int_br"  "$int_br $dmz_br"  ; do
        local in=${pair% *} out=${pair#* }
        sudo iptables -I DOCKER-USER -i "$in" -o "$out" -j ACCEPT 2>/dev/null || true
    done
    # Always end with the default RETURN
    sudo iptables -A DOCKER-USER -j RETURN 2>/dev/null || true
}

cmd_up() {
    # 플래그 파싱 — --with-windows (환경변수 WITH_WINDOWS=1).
    # secuops-easy GUI 3종은 default 로 자동 배포 (SKIP_SECUOPS_EASY=1 으로 비활성).
    local with_windows=0
    for arg in "$@"; do
        case "$arg" in
            --with-windows|--windows) with_windows=1 ;;
        esac
    done
    [ "${WITH_WINDOWS:-0}" = "1" ] && with_windows=1

    cmd_check_docker
    cmd_check_network
    cmd_check_kernel
    ensure_env
    ensure_ssh_keys
    ensure_opencti_env || true   # OpenCTI overlay 활성화 시점에 필요
    ensure_misp_env || true       # MISP overlay 활성화 시점에 필요
    [ "$with_windows" = "1" ] && cmd_check_kvm
    echo "[6v6] docker compose build + up — first run downloads ~15 GB of images,"
    echo "      build + start takes 20-30 min (Wazuh + 7 vuln + OpenCTI 20 + MISP 5)."
    # overlay 는 SKIP_OPENCTI=1 / SKIP_MISP=1 로 비활성. 자원 적은 학생 환경.
    COMPOSE_FILES="-f docker-compose.yaml"
    ENV_FILES="--env-file .env"
    if [ "${SKIP_OPENCTI:-0}" = "0" ] && [ -f docker-compose.opencti.yml ]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.opencti.yml"
        ENV_FILES="$ENV_FILES --env-file .env.opencti"
        echo "[6v6] OpenCTI overlay enabled (set SKIP_OPENCTI=1 to disable)"
    fi
    if [ "${SKIP_MISP:-0}" = "0" ] && [ -f docker-compose.misp.yml ]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.misp.yml"
        ENV_FILES="$ENV_FILES --env-file .env.misp"
        echo "[6v6] MISP overlay enabled (set SKIP_MISP=1 to disable)"
    fi
    if [ "${SKIP_SYSMON:-0}" = "0" ] && [ -f docker-compose.sysmon.yml ]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.sysmon.yml"
        echo "[6v6] sysmon-host overlay enabled (W11 lecture; set SKIP_SYSMON=1 to disable)"
    fi
    if [ "${SKIP_OLLAMA:-0}" = "0" ] && [ -f docker-compose.ollama.yml ]; then
        COMPOSE_FILES="$COMPOSE_FILES -f docker-compose.ollama.yml"
        echo "[6v6] Ollama overlay enabled (aisec lecture; CPU inference slow. SKIP_OLLAMA=1 to disable)"
    fi
    COMPOSE_FILES="$COMPOSE_FILES $ENV_FILES"
    # Assessor 평가 수집 레이어 — 기본 활성. SKIP_ASSESSOR=1 시 profile 미활성 → 생성 안 됨.
    PROFILES=""
    if [ "${SKIP_ASSESSOR:-0}" = "0" ]; then
        PROFILES="--profile assessor"
        echo "[6v6] Assessor 평가 수집 레이어 활성 (set SKIP_ASSESSOR=1 to disable)"
    fi
    # 외부망 공격자 attacker-ext — 기본 ON. 격리 wan망, 공개 포트로만 VM 접근(outsider).
    if [ "${SKIP_ATTACKER_EXT:-0}" = "0" ]; then
        PROFILES="$PROFILES --profile attacker-ext"
        echo "[6v6] 외부망 공격자 attacker-ext 활성 (wan, 공개 포트로만 접근; SKIP_ATTACKER_EXT=1 로 비활성)"
    fi
    # (옵션) 룰 무장 provisioner — write 표면이라 기본 OFF. SKIP_PROVISIONER=0 으로만 활성.
    if [ "${SKIP_PROVISIONER:-1}" = "0" ]; then
        PROFILES="$PROFILES --profile provisioner"
        echo "[6v6] (옵션) 룰 무장 provisioner 활성 — WRITE 서비스 (기본 OFF; SKIP_PROVISIONER=1 로 비활성)"
    fi
    docker compose $COMPOSE_FILES $PROFILES build
    docker compose $COMPOSE_FILES $PROFILES up -d
    sleep 3   # let docker create networks + bridges before we tweak iptables
    cmd_setup_forward
    echo
    echo "[6v6] up done. Wazuh stack takes 1-2 min after 'up' to fully initialize."
    echo "      Run 'bash 6v6.sh smoke' after ~2 min for full health check."
    cmd_status

    # Manager-SubAgent layer 자동 구성 (skip 시 SKIP_AGENTS=1)
    if [ "${SKIP_AGENTS:-0}" = "0" ] && [ -x agent/setup-agents.sh ]; then
        echo
        echo "[6v6] starting Manager + SubAgent layer (set SKIP_AGENTS=1 to skip)..."
        # non-fatal: agent 레이어 실패가 set -e 로 up 전체(특히 뒤의 GUI 자동배포)를 중단시키지 않도록.
        bash agent/setup-agents.sh || \
            echo "[6v6] WARN: Manager/SubAgent 레이어 구성 실패 — 위 로그 확인. 'bash 6v6.sh agents' 로 재시도 가능. (계속 진행)"
    fi

    # Windows 엔드포인트 (옵션 — --with-windows 또는 WITH_WINDOWS=1)
    if [ "$with_windows" = "1" ]; then
        echo
        echo "[6v6] starting Windows endpoint (6v6-win, user zone 10.20.33.60)..."
        echo "      first boot 30-60 min - Windows ISO download + unattended install + Sysmon/Wazuh/OpenSSH"
        echo "      watch progress: http://<VM_IP>:8006  /  completion marker: win-shared/OEM_DONE.txt"
        docker compose -f docker-compose.windows.yml up -d
        cmd_win_route_fix
    fi

    # secuops-easy 특강 GUI 3종 자동 배포 (방화벽/IPS/WAF 콘솔).
    # SKIP_SECUOPS_EASY=1 로 비활성.
    if [ "${SKIP_SECUOPS_EASY:-0}" = "0" ] && [ -x secuops-easy-deploy/deploy_all.sh ]; then
        cmd_secuops_easy_deploy
    fi

    # 재부팅 후에도 in-container GUI/SubAgent + Manager 가 자동 복구되도록 boot 서비스 활성 (idempotent).
    # SKIP_BOOT_PERSIST=1 로 비활성.
    if [ "${SKIP_BOOT_PERSIST:-0}" = "0" ]; then
        cmd_enable_boot || echo "[6v6] WARN: boot 자동복구 서비스 활성 실패 (계속 진행)"
    fi
}

cmd_secuops_easy_deploy() {
    # base 컨테이너 (fw/ips/web) ready 까지 대기 후 deploy_all.sh 호출.
    # 학생이 fw-gui/ips-gui/waf-gui.6v6.lab 으로 접속 가능하게 됨.
    echo
    echo "[6v6] secuops-easy GUI auto-deploy (set SKIP_SECUOPS_EASY=1 to disable)"
    echo "[6v6]   waiting for fw/ips/web to be ready (max 60s)..."
    local i
    for i in $(seq 1 30); do
        if docker exec 6v6-fw test -d /etc/haproxy 2>/dev/null && \
           docker exec 6v6-ips test -f /etc/suricata/suricata.yaml 2>/dev/null && \
           docker exec 6v6-web test -d /etc/modsecurity 2>/dev/null; then
            break
        fi
        sleep 2
    done
    bash secuops-easy-deploy/deploy_all.sh 2>&1 | sed 's/^/  /'
    echo "[6v6] secuops-easy GUI deployed — http://fw-gui.6v6.lab / ips-gui / waf-gui"
}

cmd_restore() {
    # 재부팅 복구 — systemd 6v6-restore.service 가 boot 시 호출.
    # 컨테이너는 restart:unless-stopped 로 자동 복귀하지만, docker exec 로 띄운
    # in-container GUI(:8080)/SubAgent(:8002) 와 호스트 Manager(:9200) 는 휘발되므로
    # 이 명령이 그 ephemeral 레이어를 재주입한다.
    echo "[6v6] restore: docker daemon 대기..."
    local i
    for i in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
    echo "[6v6] restore: fw/ips/web 컨테이너 ready 대기 (max 180s)..."
    for i in $(seq 1 60); do
        if docker exec 6v6-fw test -d /etc/haproxy 2>/dev/null && \
           docker exec 6v6-ips test -f /etc/suricata/suricata.yaml 2>/dev/null && \
           docker exec 6v6-web test -d /etc/modsecurity 2>/dev/null; then
            break
        fi
        sleep 3
    done
    # GUI 3종 재주입
    if [ "${SKIP_SECUOPS_EASY:-0}" = "0" ] && [ -x secuops-easy-deploy/deploy_all.sh ]; then
        bash secuops-easy-deploy/deploy_all.sh 2>&1 | sed 's/^/  /' || \
            echo "[6v6] WARN: GUI restore 실패"
    fi
    # SubAgent + Manager 재주입
    if [ "${SKIP_AGENTS:-0}" = "0" ] && [ -x agent/setup-agents.sh ]; then
        bash agent/setup-agents.sh || echo "[6v6] WARN: agent restore 실패"
    fi
    echo "[6v6] restore complete — GUI/SubAgent/Manager 재주입 완료."
}

cmd_enable_boot() {
    # 재부팅 시 cmd_restore 가 자동 실행되도록 systemd 서비스 설치/활성 (idempotent).
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "[6v6] systemd 없음 — boot 자동복구 skip"
        return 0
    fi
    local self repo unit
    repo="$(cd "$(dirname "$0")" && pwd)"
    self="$repo/$(basename "$0")"
    unit=/etc/systemd/system/6v6-restore.service
    sudo tee "$unit" >/dev/null <<EOF
[Unit]
Description=6v6 restore ephemeral layer (in-container GUIs + SubAgents + host Manager) after boot
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
# KillMode=process: ExecStart 종료 후에도 nohup 으로 띄운 호스트 Manager(:9200) 가
# 서비스 cgroup 정리로 함께 죽지 않도록 메인 프로세스만 관리.
KillMode=process
# HOME: systemd 환경엔 없어서 setup-agents.sh 의 \$HOME/bastion (set -u) 가 죽는다 → 명시.
Environment=HOME=/root
WorkingDirectory=$repo
ExecStart=/usr/bin/env bash $self restore
TimeoutStartSec=600

[Install]
WantedBy=multi-user.target
EOF
    sudo systemctl daemon-reload
    sudo systemctl enable 6v6-restore.service >/dev/null 2>&1
    echo "[6v6] boot 자동복구 활성 — 6v6-restore.service (재부팅 시 GUI/SubAgent/Manager 자동 재주입)"
}

cmd_disable_boot() {
    command -v systemctl >/dev/null 2>&1 || return 0
    sudo systemctl disable 6v6-restore.service >/dev/null 2>&1 || true
    sudo rm -f /etc/systemd/system/6v6-restore.service
    sudo systemctl daemon-reload
    echo "[6v6] boot 자동복구 비활성 — 6v6-restore.service 제거"
}

cmd_win_route_fix() {
    # dockurr/windows 컨테이너의 default GW 변경: docker bridge .254 → ips (10.20.33.1).
    # 게스트 OS 가 dockurr NAT 모드로 outbound 패킷을 컨테이너로 보내면, 컨테이너가
    # 자신의 default GW 로 SNAT 송신한다. 기본 docker bridge GW(.254=docker host) 로
    # 보내면 다른 zone(dmz/int) 으로 routing 불가 → Wazuh manager(10.20.32.100) 도달 X.
    # ips 의 user IP(10.20.33.1) 로 변경하면 ips 가 dmz/int 로 forward + SNAT.
    # (컨테이너 재시작 시 docker 가 default GW 복구 → cmd_windows up 마다 재적용 필요.)
    echo "[6v6] waiting 10s for 6v6-win container to be ready..."
    sleep 10
    if docker ps --format '{{.Names}}' | grep -q '^6v6-win$'; then
        docker exec 6v6-win sh -c \
            "ip route del default 2>/dev/null; ip route add default via 10.20.33.1" \
            2>/dev/null && echo "[6v6] 6v6-win default route -> 10.20.33.1 (ips)" \
                        || echo "[6v6] WARN: failed to change 6v6-win default route (check manually)"
    fi
}

cmd_check_kvm() {
    if [ ! -e /dev/kvm ]; then
        echo "[6v6] X /dev/kvm missing - Windows endpoint requires KVM acceleration."
        echo "      1) Enable virtualization (VT-x / AMD-V) in BIOS/UEFI"
        echo "      2) sudo apt install -y qemu-kvm"
        echo "      3) sudo modprobe kvm_intel  (or kvm_amd)"
        echo "      To skip Windows entirely, run 'bash 6v6.sh up' without --with-windows."
        exit 1
    fi
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        echo "[6v6] WARN: no rw permission on /dev/kvm for current user."
        echo "      Windows container may fail to start. Fix:"
        echo "      sudo usermod -aG kvm \$USER && newgrp kvm"
    fi
    local ram_avail
    ram_avail=$(awk '/^MemAvailable:/ {print int($2/1024/1024)}' /proc/meminfo 2>/dev/null || echo 0)
    if [ "${ram_avail:-0}" -lt 5 ]; then
        echo "[6v6] WARN: only ${ram_avail}G RAM available - tight for Windows 4G + 6v6 stack."
        echo "      Consider adding swap or stopping some containers."
    fi
}

cmd_windows() {
    # Windows 엔드포인트 후속 관리 — up/down/status/logs
    [ -f docker-compose.windows.yml ] || { echo "[6v6] docker-compose.windows.yml not found"; exit 1; }
    local sub="${1:-status}"
    case "$sub" in
        up)
            cmd_check_docker
            cmd_check_kvm
            docker compose -f docker-compose.windows.yml up -d
            cmd_win_route_fix
            echo "[6v6] watch progress: http://$(vm_ip):8006  /  completion marker: win-shared/OEM_DONE.txt"
            ;;
        down)    docker compose -f docker-compose.windows.yml down ;;
        destroy) docker compose -f docker-compose.windows.yml down -v
                 echo "[6v6] win-storage/ and win-shared/ dirs not deleted (disk image preserved)" ;;
        status)
            if docker ps --format '{{.Names}}' | grep -q '^6v6-win$'; then
                docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' --filter name=^6v6-win$
                [ -f win-shared/OEM_DONE.txt ] && echo "[6v6] OEM complete (Sysmon + Wazuh agent + OpenSSH installed)" \
                                              || echo "[6v6] OEM in progress - watch boot at http://$(vm_ip):8006"
            else
                echo "[6v6] 6v6-win not running - start with 'bash 6v6.sh windows up'"
            fi
            ;;
        logs)    docker compose -f docker-compose.windows.yml logs -f --tail=100 ;;
        *) echo "Usage: bash 6v6.sh windows {up|down|destroy|status|logs}"; exit 1 ;;
    esac
}

cmd_agents() {
    # 수동 호출 — 컨테이너 재가동 없이 agent layer 만 갱신
    [ -x agent/setup-agents.sh ] || { echo "[6v6] agent/setup-agents.sh not found"; exit 1; }
    bash agent/setup-agents.sh "$@"
}

cmd_down() {
    [ -f docker-compose.windows.yml ] && \
        docker compose -f docker-compose.windows.yml down 2>/dev/null || true
    docker compose down
}

cmd_destroy() {
    [ -f docker-compose.windows.yml ] && \
        docker compose -f docker-compose.windows.yml down -v 2>/dev/null || true
    docker compose down -v --rmi local
    echo "[6v6] containers + volumes + built images all removed."
    echo "      (Windows: win-storage/ and win-shared/ dirs preserved - delete manually if needed)"
}

cmd_logs() {
    local svc="${1:-}"
    if [ -z "$svc" ]; then
        echo "Usage: bash 6v6.sh logs <bastion|secu|web|juiceshop|dvwa|neobank|govportal|mediforum|adminconsole|aicompanion|siem|attacker|portal>"
        exit 1
    fi
    docker compose logs -f --tail=100 "$svc"
}

cmd_status() {
    ensure_env
    local IP="$(vm_ip)"
    [ -z "$IP" ] && IP="<VM_IP>"
    echo
    echo "================================================================"
    echo " 6v6 Lab Environment — VM IP: $IP"
    echo "================================================================"
    echo
    docker compose --profile assessor --profile provisioner --profile attacker-ext ps --format 'table {{.Name}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null || true
    # Windows 엔드포인트 (옵션) — base compose 와 분리돼 있어 별도로 보여줌
    if docker ps --format '{{.Names}}' | grep -q '^6v6-win$'; then
        docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}' --filter name=^6v6-win$ | tail -n +2
    fi
    echo
    echo "--- Browser access (all via Apache vhosts) --------------------"
    echo "  http://6v6.lab/              Landing page (or http://$IP/)"
    echo "  http://juice.6v6.lab/        OWASP Juice Shop"
    echo "  http://dvwa.6v6.lab/         DVWA"
    echo "  http://neobank.6v6.lab/      NeoBank"
    echo "  http://govportal.6v6.lab/    GovPortal"
    echo "  http://mediforum.6v6.lab/    MediForum"
    echo "  http://admin.6v6.lab/        AdminConsole"
    echo "  http://ai.6v6.lab/           AICompanion"
    echo "  http://portal.6v6.lab/       Admin Portal"
    echo "  http://siem.6v6.lab/         SIEM (Wazuh lite UI)"
    echo "  http://bastion.6v6.lab/health  Bastion API"
    echo "  http://assessor.6v6.lab/health Assessor (읽기 전용 평가 수집 API, X-API-Key)"
    echo "  http://fw-gui.6v6.lab/       방화벽 콘솔 (nftables 교육용 GUI)"
    echo "  http://ips-gui.6v6.lab/      IPS 콘솔 (Suricata 교육용 GUI)"
    echo "  http://waf-gui.6v6.lab/      WAF 콘솔 (ModSecurity 교육용 GUI)"
    echo
    echo "  Direct port access (debug, bypasses Apache):"
    echo "    http://$IP:8000/  http://$IP:5601/  http://$IP:9100/health"
    echo
    echo "  Add to student PC hosts file (/etc/hosts on linux/mac,"
    echo "  C:\\Windows\\System32\\drivers\\etc\\hosts on Windows):"
    echo "  $IP  6v6.lab juice.6v6.lab dvwa.6v6.lab neobank.6v6.lab govportal.6v6.lab mediforum.6v6.lab admin.6v6.lab ai.6v6.lab portal.6v6.lab"
    echo "  $IP  siem.6v6.lab bastion.6v6.lab assessor.6v6.lab fw-gui.6v6.lab ips-gui.6v6.lab waf-gui.6v6.lab"
    echo "  ★ 두 줄 각각이 IP 로 시작해야 함. 한 줄로 길게 넣다가 에디터에서 줄바꿈되면 둘째 줄"
    echo "    (siem/콘솔)에 IP 가 빠져 그 항목만 '안 열림'. juice~portal 만 되고 siem 이후가"
    echo "    안 열리면 99% 이 hosts 줄바꿈 문제 (각 줄을 IP 로 시작하게 나눠 넣으면 해결)."
    echo
    echo "--- SSH (ProxyJump) --------------------------------------------"
    echo "  ssh -p 2204 ccc@$IP            # bastion (jump host)"
    echo "  ssh -p 2202 ccc@$IP            # attacker (ext, insider — 내부 발판)"
    echo "  ssh -p 2203 ccc@$IP            # attacker-ext (wan, outsider — 공개 포트로만; SKIP_ATTACKER_EXT=1 로 비활성)"
    echo "  ssh -J ccc@$IP:2204 ccc@10.20.30.1     # fw  (ext, alias secu)"
    echo "  ssh -J ccc@$IP:2204 ccc@10.20.31.2     # ips (pipe)"
    echo "  ssh -J ccc@$IP:2204 ccc@10.20.32.80    # web (dmz)"
    echo "  ssh -J ccc@$IP:2204 ccc@10.20.32.100   # siem (dmz)"
    echo "  password: ccc"
    echo
}

check_url() {
    local label="$1" url="$2"
    local code
    code=$(curl -sk -o /dev/null -m 5 -w '%{http_code}' "$url" 2>/dev/null || echo "000")
    if [[ "$code" =~ ^(200|301|302|307|308|401|403)$ ]]; then
        printf "  [OK]   %-22s %s (HTTP %s)\n" "$label" "$url" "$code"
    else
        printf "  [FAIL] %-22s %s (HTTP %s)\n" "$label" "$url" "$code"
    fi
}

cmd_smoke() {
    # smoke 는 best-effort 진단 — 각 항목이 자체 [OK]/[FAIL] 을 출력한다. 스크립트 전역
    # 'set -euo pipefail' 하에서는 wazuh-control status 의 non-zero(클러스터/maild 등 미기동)
    # + pipefail 이 set -e 로 smoke 를 중도 종료시키므로, 이 함수 안에서는 errexit/pipefail 해제.
    set +e +o pipefail
    ensure_env
    local IP="$(vm_ip)"
    [ -z "$IP" ] && { echo "[6v6] cannot detect VM IP"; exit 1; }
    echo
    echo "[6v6] smoke test (VM_IP=$IP)"
    echo "--- external ports (4-tier: fw HAProxy is the only ingress) ----"
    check_url "landing"          "http://$IP/"
    check_url "bastion API"      "http://$IP:9100/health"
    echo
    echo "--- vhost reverse proxy (Host header — fw HAProxy routing) -----"
    for h in juice dvwa neobank govportal mediforum admin ai portal siem bastion; do
        local code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' \
            -H "Host: $h.6v6.lab" "http://$IP/" 2>/dev/null || echo 000)
        # 200/302 = endpoint OK; 404 = backend alive (e.g. bastion API root); 503 still booting
        if [[ "$code" =~ ^(200|301|302|307|308|401|403|404)$ ]]; then
            printf "  [OK]   %-22s HTTP %s\n" "$h.6v6.lab" "$code"
        else
            printf "  [FAIL] %-22s HTTP %s (backend may still be booting)\n" "$h.6v6.lab" "$code"
        fi
    done
    echo
    echo "--- 교육용 콘솔 (방화벽/IPS/WAF GUI — 실제 콘솔 페이지 title 확인) --------"
    # 200 만으로는 부족: HAProxy 라우트 누락 시 default_backend(waf)→web 랜딩으로 fallthrough 하여
    # 거짓 200 이 난다(과거 콘솔 미접속 버그의 원인). title 에 '콘솔' 이 있어야 진짜 콘솔이다.
    for g in fw ips waf; do
        local ctitle=$(curl -s -m 5 -H "Host: $g-gui.6v6.lab" "http://$IP/" 2>/dev/null \
            | grep -ioE '<title>[^<]*</title>' | head -1)
        if echo "$ctitle" | grep -q '콘솔'; then
            printf "  [OK]   %-22s %s\n" "$g-gui.6v6.lab" "$ctitle"
        else
            printf "  [FAIL] %-22s '%s' (콘솔 아님 — 랜딩 fallthrough? 'bash 6v6.sh up' 로 재빌드)\n" "$g-gui.6v6.lab" "${ctitle:-no-response}"
        fi
    done
    echo
    echo "--- container health -------------------------------------------"
    for c in 6v6-bastion 6v6-attacker 6v6-fw 6v6-ips 6v6-web 6v6-juiceshop 6v6-dvwa 6v6-neobank 6v6-govportal 6v6-mediforum 6v6-adminconsole 6v6-aicompanion 6v6-wazuh-indexer 6v6-siem 6v6-wazuh-dashboard 6v6-portal; do
        if docker ps --format '{{.Names}}' | grep -q "^$c$"; then
            printf "  [OK]   %-19s %s\n" "$c" "$(docker ps --format '{{.Status}}' --filter name=^$c$)"
        else
            printf "  [FAIL] %-19s container not running\n" "$c"
        fi
    done
    echo
    echo "--- Wazuh full stack -------------------------------------------"
    if docker ps --format '{{.Names}}' | grep -q '^6v6-siem$'; then
        local running
        running=$(docker exec 6v6-siem /var/ossec/bin/wazuh-control status 2>/dev/null \
                  | grep -c 'is running' 2>/dev/null | head -1 | tr -dc 0-9)
        running=${running:-0}
        if [ "${running:-0}" -ge 6 ] 2>/dev/null; then
            printf "  [OK]   wazuh-manager daemons %s running\n" "$running"
        else
            printf "  [WARN] wazuh-manager daemons %s running (still booting?)\n" "$running"
        fi
        local agents
        agents=$(docker exec 6v6-siem /var/ossec/bin/agent_control -l 2>/dev/null \
                 | grep -cE '^\s+ID:' 2>/dev/null | head -1 | tr -dc 0-9)
        agents=${agents:-0}
        if [ "${agents:-0}" -ge 3 ] 2>/dev/null; then
            printf "  [OK]   Wazuh agents enrolled  %s (target 3+: fw/ips/web)\n" "$agents"
        else
            printf "  [WARN] Wazuh agents enrolled %s (target 3+: fw/ips/web)\n" "$agents"
        fi
        if docker exec 6v6-siem test -s /var/ossec/logs/alerts/alerts.json 2>/dev/null; then
            local alines=$(docker exec 6v6-siem wc -l /var/ossec/logs/alerts/alerts.json 2>/dev/null | awk '{print $1}')
            printf "  [OK]   alerts.json lines      %s\n" "$alines"
        else
            printf "  [INFO] alerts.json empty      — fire test traffic, recheck\n"
        fi
    else
        echo "  [FAIL] siem (wazuh-manager) not running"
    fi
    # indexer (OpenSearch) cluster health
    if docker ps --format '{{.Names}}' | grep -q '^6v6-wazuh-indexer$'; then
        local idx_status=$(docker exec 6v6-wazuh-indexer curl -sk -m 5 \
            -u admin:SecretPassword https://localhost:9200/_cluster/health 2>/dev/null \
            | grep -oE '"status":"[a-z]+"' | head -1)
        if echo "$idx_status" | grep -qE 'green|yellow'; then
            printf "  [OK]   wazuh-indexer cluster %s\n" "$idx_status"
        else
            printf "  [WARN] wazuh-indexer cluster %s (still booting?)\n" "${idx_status:-no-response}"
        fi
    fi
    # dashboard (Kibana fork)
    if docker ps --format '{{.Names}}' | grep -q '^6v6-wazuh-dashboard$'; then
        local d_code=$(docker exec 6v6-wazuh-dashboard curl -sk -m 5 \
            -o /dev/null -w '%{http_code}' https://localhost:5601/app/wazuh 2>/dev/null || echo 000)
        if [[ "$d_code" =~ ^(200|302)$ ]]; then
            printf "  [OK]   wazuh-dashboard listen (HTTP %s on :5601)\n" "$d_code"
        else
            printf "  [WARN] wazuh-dashboard responded HTTP %s\n" "$d_code"
        fi
    fi
    echo
    echo "--- SSH bastion ------------------------------------------------"
    # BatchMode=yes 는 password 인증을 비활성화해 sshpass 를 무력화한다(→ 항상 실패하던 거짓 [WARN]).
    # 제거하고 PubkeyAuthentication=no 로 password 경로만 검증한다(bastion 은 password 로그인 허용).
    local ssh_opt='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=4'
    if command -v sshpass >/dev/null 2>&1; then
        if sshpass -p "${SSH_PASS:-ccc}" ssh -p 2204 $ssh_opt \
              -o PreferredAuthentications=password -o PubkeyAuthentication=no \
              "${SSH_USER:-ccc}@$IP" 'true' 2>/dev/null; then
            echo "  [OK]   bastion SSH (port 2204)"
        else
            echo "  [WARN] bastion SSH check failed"
        fi
    else
        echo "  [SKIP] sshpass not installed — manually verify 'ssh -p 2204 ccc@$IP'"
    fi
    echo
    echo "--- Assessor (읽기 전용 평가 수집) ------------------------------"
    if docker ps --format '{{.Names}}' | grep -q '^6v6-assessor$'; then
        # /health (인증 불필요) — Host 헤더로 fw HAProxy 경유
        local a_code=$(curl -s -o /dev/null -m 5 -w '%{http_code}' \
            -H "Host: assessor.6v6.lab" "http://$IP/health" 2>/dev/null || echo 000)
        if [ "$a_code" = "200" ]; then
            printf "  [OK]   assessor /health        HTTP %s\n" "$a_code"
        else
            printf "  [WARN] assessor /health        HTTP %s (still booting?)\n" "$a_code"
        fi
        # 샘플 check 1건: web 의 apache2.conf file_exists (X-API-Key, read-only)
        local sample
        sample=$(curl -s -m 8 -H "Host: assessor.6v6.lab" \
            -H "X-API-Key: ${API_KEY:-ccc-api-key-2026}" \
            -H "Content-Type: application/json" \
            -X POST "http://$IP/assess" \
            -d '{"checks":[{"id":"smoke1","type":"file_exists","target":"web","params":{"path":"/etc/apache2/apache2.conf"}}]}' 2>/dev/null)
        if echo "$sample" | grep -q '"passed": *true'; then
            printf "  [OK]   sample /assess file_exists(web) → passed (부작용 0)\n"
        elif echo "$sample" | grep -q '"results"'; then
            printf "  [WARN] sample /assess 응답하나 passed 아님: %s\n" "$(echo "$sample" | head -c 160)"
        else
            printf "  [WARN] sample /assess 무응답 (assessor 부팅중 또는 API key 불일치)\n"
        fi
        # 샘플 /activity 1건: 최근 24h 보안 알림 리스트 반환 (모니터링 피드)
        local act
        act=$(curl -s -m 8 -H "Host: assessor.6v6.lab" \
            -H "X-API-Key: ${API_KEY:-ccc-api-key-2026}" \
            -H "Content-Type: application/json" \
            -X POST "http://$IP/activity" \
            -d '{"since_sec":86400,"limit":50,"want":["alerts","commands","services"]}' 2>/dev/null)
        if echo "$act" | grep -q '"collected_at"'; then
            local n_al n_cmd
            n_al=$(echo "$act" | grep -o '"rule_id"' | wc -l | tr -dc 0-9)
            n_cmd=$(echo "$act" | grep -o '"cmd"' | wc -l | tr -dc 0-9)
            printf "  [OK]   sample /activity → alerts=%s commands=%s + services 요약 반환\n" "${n_al:-0}" "${n_cmd:-0}"
        else
            printf "  [WARN] sample /activity 무응답: %s\n" "$(echo "$act" | head -c 160)"
        fi
    else
        echo "  [SKIP] 6v6-assessor not running (SKIP_ASSESSOR=1?)"
    fi
    echo
}

cmd_help() {
    cat <<'HELP'
Usage: bash 6v6.sh <command>

  install   auto-install docker + compose + helpers (Debian/Ubuntu)
            -> first time only. Re-login or 'newgrp docker' after.
  up [--with-windows]  build + start. With --with-windows (or WITH_WINDOWS=1)
                       also starts 6v6-win (Windows 11 tiny11, user 10.20.33.60).
                       Requires KVM. First boot 30-60 min.
  down      stop containers (volumes preserved). Windows also taken down.
  destroy   remove containers + volumes + images
  status    container status + access info (Windows included)
  smoke     external ports + container + Wazuh + SSH health checks
  logs <svc>  follow container logs
  windows {up|down|destroy|status|logs}
            manage Windows endpoint separately (after base is up)
  agents [--skip]   (re)deploy SubAgent layer + host Manager (:9200)
  restore   재부팅 후 ephemeral 레이어(in-container GUI/SubAgent + Manager) 재주입.
            보통 boot 시 6v6-restore.service 가 자동 호출 (수동 실행도 가능).
  enable-boot / disable-boot
            재부팅 자동복구 systemd 서비스(6v6-restore.service) 활성/비활성.
            'up' 시 자동 활성 (SKIP_BOOT_PERSIST=1 로 생략).

Quick start (fresh Linux VM):
  bash 6v6.sh install                # auto-install docker + helpers
  newgrp docker                      # or open new terminal
  bash 6v6.sh up                     # 15 containers (Windows excluded)
  bash 6v6.sh up --with-windows      # 16 containers (+ Windows tiny11, user zone)
  bash 6v6.sh status                 # show access info
  bash 6v6.sh smoke                  # health check

Services: bastion / attacker / fw / ips / web / siem / wazuh-indexer /
          wazuh-dashboard / portal / assessor / juiceshop / dvwa / neobank /
          govportal / mediforum / adminconsole / aicompanion
Optional: 6v6-win (Windows 11 tiny11 user PC, user 10.20.33.60) -- --with-windows

Toggles (env): SKIP_ASSESSOR=1 (평가 수집 레이어 생략) / SKIP_AGENTS / SKIP_SECUOPS_EASY
          / SKIP_OPENCTI / SKIP_MISP / SKIP_SYSMON / SKIP_OLLAMA / SKIP_BOOT_PERSIST
Assessor: 읽기 전용 평가 수집 API (CC/tubewar 채점용). http://assessor.6v6.lab/
          POST /assess + X-API-Key. 자세한 내용 ASSESSOR.md.
HELP
}

case "${1:-help}" in
    install)  cmd_install ;;
    up)       shift; cmd_up "$@" ;;
    down)     cmd_down ;;
    destroy)  cmd_destroy ;;
    status)   cmd_status ;;
    smoke)    cmd_smoke ;;
    logs)     shift; cmd_logs "$@" ;;
    agents)   shift; cmd_agents "$@" ;;
    restore)      cmd_restore ;;
    enable-boot)  cmd_enable_boot ;;
    disable-boot) cmd_disable_boot ;;
    windows)  shift; cmd_windows "$@" ;;
    help|-h|--help) cmd_help ;;
    *) cmd_help; exit 1 ;;
esac
