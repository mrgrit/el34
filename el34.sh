#!/usr/bin/env bash
# el34 — 단일 설치/운영 스크립트.  갓 설치한 Ubuntu → 한 방 배포.
#   sudo ./el34.sh install     # Docker + daemon.json(userland-proxy=false)
#   ./el34.sh up               # 인증서·env 생성 → build → core+overlay up → net glue → systemd → sigma
#   ./el34.sh down             # 전체 내림 (-v 로 볼륨까지)
#   ./el34.sh net              # 호스트 네트워크 글루만 재적용 (재생성 후)
#   ./el34.sh certs|env|sigma  # 개별 단계
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

WEB_HOST_IP="${WEB_HOST_IP:-192.168.0.161}"     # ens37 — 웹/dmz 외부 진입 (compose 와 일치)
INT_HOST_IP="${INT_HOST_IP:-192.168.136.145}"   # ens38 — 내부전용 GUI/SIEM 바인딩
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"

# ───────────────────────────────────────────────── helpers
ensure_env() {
    [ -f .env ] || { cp .env.example .env; echo "[el34] .env 생성(.env.example 복사) — LLM_BASE_URL 등 값 확인 권장"; }
    grep -q '^LLM_MANAGER_MODEL='  .env || echo 'LLM_MANAGER_MODEL=gemma3:4b'  >> .env
    grep -q '^LLM_SUBAGENT_MODEL=' .env || echo 'LLM_SUBAGENT_MODEL=gemma3:4b' >> .env
}

ensure_ssh_keys() {
    mkdir -p keys
    if [ ! -f keys/id_rsa ]; then
        ssh-keygen -t ed25519 -f keys/id_rsa -N "" -C "el34-bastion@auto" >/dev/null 2>&1
        echo "[el34] SSH 키 생성(keys/id_rsa) — 컨테이너 간 password-less SSH"
    fi
    chmod 600 keys/id_rsa 2>/dev/null || true; chmod 644 keys/id_rsa.pub 2>/dev/null || true
}

ensure_misp_env() {
    [ -f .env.misp ] && return 0
    [ -f .env.misp.example ] || return 0
    cp .env.misp.example .env.misp
    sed -i "s|^BASE_URL=.*|BASE_URL=https://${INT_HOST_IP}:8443|" .env.misp
    sed -i "s|^MYSQL_PASSWORD=.*|MYSQL_PASSWORD=$(openssl rand -hex 16)|" .env.misp
    sed -i "s|^MYSQL_ROOT_PASSWORD=.*|MYSQL_ROOT_PASSWORD=$(openssl rand -hex 16)|" .env.misp
    sed -i "s|^DISABLE_IPV6=.*|DISABLE_IPV6=true|" .env.misp
    grep -q "^CORE_HTTP_PORT="  .env.misp || echo "CORE_HTTP_PORT=8880"  >> .env.misp
    grep -q "^CORE_HTTPS_PORT=" .env.misp || echo "CORE_HTTPS_PORT=8443" >> .env.misp
    chmod 600 .env.misp
    echo "[el34] .env.misp 생성 (내부전용 ${INT_HOST_IP}:8443)"
}

ensure_opencti_env() {
    [ -f .env.opencti ] && return 0
    command -v uuidgen >/dev/null || { echo "[el34] uuid-runtime 필요: sudo apt install -y uuid-runtime"; return 1; }
    cat > .env.opencti <<ENV
OPENCTI_ADMIN_EMAIL=admin@opencti.io
OPENCTI_ADMIN_PASSWORD=$(openssl rand -hex 12)
OPENCTI_ADMIN_TOKEN=$(uuidgen)
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(uuidgen)
OPENCTI_ENCRYPTION_KEY=$(openssl rand -base64 32)
OPENCTI_BASE_URL=http://${INT_HOST_IP}:8080
OPENCTI_EXTERNAL_SCHEME=http
OPENCTI_HOST=${INT_HOST_IP}
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
    echo "[el34] .env.opencti 생성 (내부전용 ${INT_HOST_IP}:8080)"
}

ensure_certs() {
    # Wazuh TLS 인증서 생성 (레포 미포함 → fresh 배포 시 생성).  wazuh-certs-generator 사용.
    if [ -f wazuh-config/certs/root-ca.pem ] && [ -f wazuh-config/certs/wazuh.manager.pem ]; then
        echo "[el34] 인증서 이미 존재 — 생성 건너뜀"; return 0
    fi
    echo "[el34] Wazuh 인증서 생성 (wazuh-certs-generator)"
    mkdir -p wazuh-config/certs
    docker run --rm \
        -v "$(pwd)/wazuh-config/certs:/certificates/" \
        -v "$(pwd)/wazuh-config/config/certs.yml:/config/certs.yml" \
        wazuh/wazuh-certs-generator:0.0.2 2>&1 | sed 's/^/  /' || true
    # 생성물 권한 평탄화 (generator 가 UID/600 으로 잠금 → 마운트·읽기 가능하게)
    $SUDO chown -R "$(id -u):$(id -g)" wazuh-config/certs 2>/dev/null || true
    ( cd wazuh-config/certs
      # ── 단일 CA 통일 ──────────────────────────────────────────────
      # generator 는 indexer/dashboard(root-ca) 와 manager(root-ca-manager) 를 별도 CA 로 만든다.
      # 그러면 filebeat(manager)↔indexer mTLS 가 서로 다른 CA 라 실패한다. 6v6 검증 레이아웃대로
      # manager 인증서를 root-ca 로 '재발급'하여 전 노드가 단일 root-ca 를 신뢰하게 통일한다.
      openssl req -new -key wazuh.manager-key.pem -out /tmp/_mgr.csr \
        -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=wazuh.manager" 2>/dev/null
      printf "subjectAltName=DNS:wazuh.manager,DNS:wazuh-manager,DNS:siem,DNS:localhost,IP:127.0.0.1\n" > /tmp/_mgr.ext
      openssl x509 -req -in /tmp/_mgr.csr -CA root-ca.pem -CAkey root-ca.key -CAcreateserial \
        -days 3650 -sha256 -extfile /tmp/_mgr.ext -out wazuh.manager.pem 2>/dev/null
      cp -f root-ca.pem root-ca-manager.pem; cp -f root-ca.key root-ca-manager.key
      rm -f /tmp/_mgr.csr /tmp/_mgr.ext root-ca.srl
      chmod 644 *.pem 2>/dev/null || true; chmod 600 *-key.pem *.key 2>/dev/null || true )
    echo "[el34] 인증서 준비 (단일 CA 통일): $(ls wazuh-config/certs/*.pem 2>/dev/null | wc -l) .pem"
}

# ───────────────────────────────────────────────── install (Docker + daemon.json)
cmd_install() {
    echo "[el34] === install: Docker + daemon.json(userland-proxy=false) ==="
    if ! command -v docker >/dev/null 2>&1; then
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        $SUDO sh /tmp/get-docker.sh
        $SUDO usermod -aG docker "$USER" || true
        echo "[el34] Docker 설치 완료 — docker 그룹 반영 위해 재로그인/새 셸 필요할 수 있음"
    fi
    # daemon.json: userland-proxy=false (출처 IP 보존 핵심) + DNS
    local dj=/etc/docker/daemon.json tmp; tmp=$(mktemp)
    if [ -f "$dj" ] && command -v jq >/dev/null 2>&1; then
        $SUDO jq '. + {"userland-proxy": false, "dns": ["8.8.8.8","1.1.1.1"]}' "$dj" > "$tmp"
    else
        printf '{\n  "userland-proxy": false,\n  "dns": ["8.8.8.8", "1.1.1.1"]\n}\n' > "$tmp"
    fi
    $SUDO cp "$dj" "${dj}.bak.$(date +%s)" 2>/dev/null || true
    $SUDO cp "$tmp" "$dj"; rm -f "$tmp"
    $SUDO systemctl restart docker
    sleep 4
    echo "[el34] docker: $(docker --version 2>/dev/null)  userland-proxy=false 적용"
}

# ───────────────────────────────────────────────── host network glue
cmd_net() { exec ./el34-net.sh; }

install_systemd() {
    $SUDO cp el34-net.service /etc/systemd/system/el34-net.service
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable --now el34-net >/dev/null 2>&1 || true
    echo "[el34] el34-net.service 설치·활성 (재부팅 후 체인 자동 보존)"
}

# ───────────────────────────────────────────────── sigma
cmd_sigma() { (cd sigma && SIEM_CONTAINER=el34-siem ./install-sigma.sh); }

# ───────────────────────────────────────────────── up (전체)
OVERLAY="-f docker-compose.yaml -f docker-compose.opencti.yml -f docker-compose.misp.yml -f docker-compose.sysmon.yml"
ENVF="--env-file .env --env-file .env.opencti --env-file .env.misp"

cmd_up() {
    command -v docker >/dev/null || { echo "[el34] Docker 없음 — 먼저 'sudo ./el34.sh install'"; exit 1; }
    ensure_env; ensure_ssh_keys; ensure_certs; ensure_misp_env; ensure_opencti_env
    echo "[el34] === build (최초 ~수GB pull) ==="
    docker compose build
    echo "[el34] === core up ==="
    docker compose up -d
    ./el34-net.sh
    echo "[el34] === overlay up (opencti→misp 순서: redis=valkey 충돌 방지) ==="
    docker compose $OVERLAY $ENVF up -d
    ./el34-net.sh           # 오버레이가 core 재생성 → 글루 재적용
    install_systemd
    echo "[el34] === sigma 적재 ==="
    cmd_sigma || echo "[el34] WARN: sigma 적재 실패(나중에 ./el34.sh sigma)"
    echo "[el34] ✅ up 완료. 웹 진입 http://${WEB_HOST_IP}:8001.. / 내부 GUI http://${INT_HOST_IP}:{5601,8000,8081-8083,8080}"
}

cmd_down() { docker compose $OVERLAY $ENVF down "${1:-}" 2>/dev/null || docker compose down "${1:-}"; }

case "${1:-}" in
    install) cmd_install ;;
    up)      cmd_up ;;
    down)    shift; cmd_down "${1:-}" ;;
    net)     cmd_net ;;
    certs)   ensure_certs ;;
    env)     ensure_env; ensure_misp_env; ensure_opencti_env ;;
    sigma)   cmd_sigma ;;
    *) echo "usage: $0 {install|up|down [-v]|net|certs|env|sigma}"; exit 1 ;;
esac
