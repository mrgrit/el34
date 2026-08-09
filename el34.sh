#!/usr/bin/env bash
# el34 — 단일 설치/운영 스크립트.  갓 설치한 Ubuntu → 한 방 배포.
#   sudo ./el34.sh install     # Docker + daemon.json(userland-proxy=false)
#   ./el34.sh up               # 인증서·env 생성 → build → core+overlay up → net glue → systemd → sigma
#   ./el34.sh down             # 전체 내림 (-v 로 볼륨까지)
#   ./el34.sh net              # 호스트 네트워크 글루만 재적용 (재생성 후)
#   ./el34.sh certs|env|sigma  # 개별 단계
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

# 웹 진입 publish 바인딩 IP.
#   · 미지정: up 시 VM 실제 IP 자동감지 → .env(WEB_HOST_IP) 기록 (강의실/DHCP 브리지 VM).
#     학생 hosts(el34.lab→VM_IP) 와 바인딩 IP 가 일치해 VM 밖에서 접속 가능.
#   · 명시 지정(예: WEB_HOST_IP=192.168.0.161 ./el34.sh up): 그대로 존중 (2-NIC .151 레거시).
WEB_HOST_IP_EXPLICIT=""; [ -n "${WEB_HOST_IP:-}" ] && WEB_HOST_IP_EXPLICIT=1
WEB_HOST_IP="${WEB_HOST_IP:-}"
INT_HOST_IP="${INT_HOST_IP:-192.168.136.145}"   # ens38 — 내부전용 GUI/SIEM 바인딩(dummy, VM 자체 Firefox)
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
REAL_USER="${SUDO_USER:-$(id -un)}"             # sudo 로 재실행돼도 원래 사용자 (파일 소유 복원용)

# ───────────────────────────────────────────────── helpers
ensure_env() {
    [ -f .env ] || { cp .env.example .env; echo "[el34] .env 생성(.env.example 복사) — LLM_BASE_URL 등 값 확인 권장"; }
    grep -q '^LLM_MANAGER_MODEL='  .env || echo 'LLM_MANAGER_MODEL=gpt-oss:120b' >> .env
    grep -q '^LLM_SUBAGENT_MODEL=' .env || echo 'LLM_SUBAGENT_MODEL=qwen3:8b'   >> .env
}

detect_primary_ip() {
    # 기본 라우트로 나가는 소스 IP = 브리지/DHCP 로 받은 VM 실제 IP (프롬프트 기본값 제안용)
    ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}'
}

valid_ip() {
    # IPv4 형식 + 각 옥텟 0-255 (0.0.0.0 도 허용 = 모든 인터페이스)
    case "$1" in
        *[!0-9.]*|.*|*.|*..*) return 1 ;;
    esac
    local o1 o2 o3 o4 IFS=.
    read -r o1 o2 o3 o4 <<<"$1"
    [ -n "$o4" ] && for o in "$o1" "$o2" "$o3" "$o4"; do [ "$o" -le 255 ] 2>/dev/null || return 1; done
}

_persist_web_host_ip() {   # $1 = ip. .env 에 기록(멱등).
    if grep -qE '^WEB_HOST_IP=' .env 2>/dev/null; then
        sed -i "s|^WEB_HOST_IP=.*|WEB_HOST_IP=$1|" .env
    else
        printf 'WEB_HOST_IP=%s\n' "$1" >> .env
    fi
}

# 웹 진입 고정 IP 를 확정한다 — 최초 setup(install) 때 사용자에게 1회 물어 .env 에 고정.
#   · 이후 up/재부팅은 .env 값을 그대로 사용(재질문 없음). 변경: WEB_HOST_IP_FORCE=1 ./el34.sh install
#   · 명시 지정(WEB_HOST_IP=x ./el34.sh ...)은 프롬프트 없이 그 값으로 고정.
#   · 비대화형(TTY 없음)이면 자동감지값으로 고정.
resolve_web_host_ip() {
    ensure_env   # .env 보장
    local existing; existing="$(grep -E '^WEB_HOST_IP=' .env 2>/dev/null | tail -1 | cut -d= -f2- || true)"

    # 1) 명시 env override — 프롬프트 없이 고정
    if [ -n "$WEB_HOST_IP_EXPLICIT" ]; then
        _persist_web_host_ip "$WEB_HOST_IP"
        echo "[el34] 웹 진입 IP 고정(명시 지정): ${WEB_HOST_IP} (.env)"; return 0
    fi
    # 2) 이미 고정돼 있고 강제변경 아님 — 그대로 사용(쭉 고정)
    if [ -n "$existing" ] && [ -z "${WEB_HOST_IP_FORCE:-}" ]; then
        WEB_HOST_IP="$existing"
        echo "[el34] 웹 진입 IP(고정) 사용: ${WEB_HOST_IP} (.env) — 변경: WEB_HOST_IP_FORCE=1 ./el34.sh install"
        return 0
    fi
    # 3) 최초 지정(또는 강제 변경) — 사용자에게 1회 질의
    local def; def="${existing:-$(detect_primary_ip || true)}"; def="${def:-0.0.0.0}"
    local ans="" ip=""
    if [ -t 0 ]; then
        echo   "[el34] ── 웹 진입 고정 IP 지정 ──────────────────────────────"
        echo   "  랜딩페이지/취약사이트(el34.lab)를 이 IP 로 노출하고, 이후 계속 이 값을 씁니다."
        echo   "  · 학생 PC hosts 파일: 'el34.lab juice.el34.lab ... → 이 IP' 로 매핑"
        echo   "  · 강의실 DHCP 환경이면 VM 에 이 IP 를 고정(static/DHCP 예약)해 두세요"
        echo   "  · 0.0.0.0 입력 시 모든 인터페이스 바인딩(VM 실제 IP 로 접속)"
        while :; do
            printf "  웹 진입 IP [기본 %s]: " "$def"
            read -r ans || ans=""
            ip="${ans:-$def}"
            if valid_ip "$ip"; then break; fi
            echo "  ✗ '$ip' 는 올바른 IPv4 가 아닙니다. 다시 입력하세요."
        done
    else
        ip="$def"
        echo "[el34] 비대화형 — 웹 진입 IP 자동감지값으로 고정: ${ip}"
    fi
    WEB_HOST_IP="$ip"
    _persist_web_host_ip "$WEB_HOST_IP"
    echo "[el34] ✅ 웹 진입 IP 고정: ${WEB_HOST_IP} (.env 기록 — 이후 up/재부팅 모두 이 값)"
}

is_wireless_if() {   # $1=iface — 무선이면 return 0
    [ -d "/sys/class/net/$1/wireless" ] && return 0
    command -v iw >/dev/null 2>&1 && iw dev 2>/dev/null | grep -qw "$1" && return 0
    return 1
}

# 입력한 웹 진입 IP 를 주 이더넷 IF 에 netplan static 으로 고정(재부팅에도 유지).
#   · 유선(브리지 VM)만 지원 — 무선/미탐지/0.0.0.0 은 skip.
#   · 적용 전 확인(원격 SSH 면 IP 변경으로 끊길 수 있어 콘솔 권장). 비대화형은 WEB_NETPLAN_STATIC=1 필요.
#   · 롤백: /etc/netplan/99-el34-static.yaml 삭제 후 netplan apply (백업은 /etc/netplan/backup-el34/).
#   · override: WEB_STATIC_IFACE / WEB_STATIC_GW / WEB_STATIC_PREFIX
#   · 테스트 seam: EL34_NETPLAN_DIR / EL34_CLOUDCFG_DIR / EL34_NETPLAN_DRYRUN
netplan_static() {
    local ip="${1:-$WEB_HOST_IP}"
    if [ -z "$ip" ] || [ "$ip" = "0.0.0.0" ]; then
        echo "[el34] WEB_HOST_IP=${ip:-(미설정)} — 모든 인터페이스 바인딩이라 static 고정 불필요(skip)"; return 0
    fi
    if ! command -v netplan >/dev/null 2>&1; then
        echo "[el34] netplan 미설치 — 자동 static 고정 skip. VM IP 를 수동으로 ${ip} 고정 권장"; return 0
    fi
    local IFACE GW PREFIX
    IFACE="${WEB_STATIC_IFACE:-$(ip -4 route show default | awk '{print $5; exit}')}"
    [ -z "$IFACE" ] && IFACE="$(ip -4 -br addr | awk '$1!="lo"{print $1; exit}')"
    if [ -z "$IFACE" ]; then echo "[el34] WARN: 주 인터페이스 미탐지 — netplan static skip"; return 0; fi
    if is_wireless_if "$IFACE"; then
        echo "[el34] WARN: ${IFACE} 는 무선 — netplan static 자동설정 미지원(유선 브리지 VM 용). skip"; return 0
    fi
    GW="${WEB_STATIC_GW:-$(ip -4 route show default | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')}"
    PREFIX="${WEB_STATIC_PREFIX:-$(ip -4 -br addr show "$IFACE" 2>/dev/null | awk '{print $3}' | head -1 | cut -d/ -f2)}"
    PREFIX="${PREFIX:-24}"
    [ -z "$GW" ] && GW="$(echo "$ip" | cut -d. -f1-3).1"

    local NPDIR="${EL34_NETPLAN_DIR:-/etc/netplan}"
    local CCDIR="${EL34_CLOUDCFG_DIR:-/etc/cloud/cloud.cfg.d}"
    local NP="$NPDIR/99-el34-static.yaml"

    echo "[el34] ── netplan static 고정 계획 ──"
    echo "        인터페이스 : ${IFACE}"
    echo "        주소       : ${ip}/${PREFIX}"
    echo "        게이트웨이 : ${GW}"
    echo "        파일       : ${NP}"
    if [ -z "${EL34_NETPLAN_DRYRUN:-}" ]; then
        if [ -t 0 ]; then
            printf "  적용할까요? 원격 SSH 세션이면 IP 변경으로 끊길 수 있습니다(콘솔 권장) [y/N]: "
            local a; read -r a || a=""
            case "$a" in y|Y|yes|YES) ;; *) echo "[el34] netplan static 취소 — WEB_HOST_IP 는 .env 에만 고정됨(VM IP 수동 고정 권장)"; return 0 ;; esac
        elif [ -z "${WEB_NETPLAN_STATIC:-}" ]; then
            echo "[el34] 비대화형 — 네트워크 자동 변경 보류. 적용하려면 WEB_NETPLAN_STATIC=1 로 재실행"; return 0
        fi
    fi

    $SUDO mkdir -p "$NPDIR/backup-el34"
    local f; for f in "$NPDIR"/*.yaml "$NPDIR"/*.yml; do [ -f "$f" ] && { $SUDO cp -n "$f" "$NPDIR/backup-el34/" 2>/dev/null || true; }; done
    # cloud-init 네트워크 관리 비활성화 → static 이 재부팅에도 덮이지 않음
    $SUDO mkdir -p "$CCDIR"
    printf 'network: {config: disabled}\n' | $SUDO tee "$CCDIR/99-el34-disable-network.cfg" >/dev/null
    $SUDO tee "$NP" >/dev/null <<YAML
# el34 — 웹 진입 고정 IP static (자동 생성)
# 롤백: 이 파일 삭제 후 'sudo netplan apply' (원본 백업: backup-el34/, cloud-init 재활성은
#       /etc/cloud/cloud.cfg.d/99-el34-disable-network.cfg 삭제).
network:
  version: 2
  renderer: networkd
  ethernets:
    ${IFACE}:
      dhcp4: false
      addresses: [${ip}/${PREFIX}]
      routes:
        - to: default
          via: ${GW}
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
YAML
    $SUDO chmod 600 "$NP"

    if [ -n "${EL34_NETPLAN_DRYRUN:-}" ]; then
        echo "[el34] (dry-run) 파일 생성만 — netplan generate/apply 생략"; return 0
    fi
    if ! $SUDO netplan generate 2>&1 | sed 's/^/  netplan: /'; then
        echo "[el34] ERROR: netplan generate 실패 — ${NP} 제거(롤백)"; $SUDO rm -f "$NP"; return 1
    fi
    $SUDO netplan apply && echo "[el34] ✅ netplan static 적용: ${IFACE}=${ip}/${PREFIX} gw=${GW} (재부팅에도 유지)"
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
    # ── 권한 정규화 ── generator 가 디렉터리 0500 / 파일 0400 / UID 999 로 잠금.
    # 동작하는 el34 레이아웃 = 사용자(uid 1000) 소유 + 644(world-readable). 컨테이너(wazuh uid 1000 등)
    # 가 읽을 수 있어야 함. up 은 root 로 실행되므로 chown/chmod 가능 (REAL_USER=ccc 로 환원).
    $SUDO chown -R "$REAL_USER:$REAL_USER" wazuh-config/certs || true
    $SUDO chmod 755 wazuh-config/certs || true
    $SUDO chmod -R u+rw wazuh-config/certs/* 2>/dev/null || true
    # ── 단일 CA 통일 ── generator 는 indexer/dashboard(root-ca) 와 manager(root-ca-manager) 를
    # 별도 CA 로 만든다 → filebeat(manager)↔indexer mTLS 가 서로 다른 CA 라 실패. manager 인증서를
    # root-ca 로 재발급하여 전 노드가 단일 root-ca 를 신뢰하게 통일한다 (el34 검증 레이아웃).
    local cd_certs="wazuh-config/certs"
    openssl req -new -key "$cd_certs/wazuh.manager-key.pem" -out /tmp/_mgr.csr \
        -subj "/C=US/L=California/O=Wazuh/OU=Wazuh/CN=wazuh.manager" 2>/dev/null || true
    printf "subjectAltName=DNS:wazuh.manager,DNS:wazuh-manager,DNS:siem,DNS:localhost,IP:127.0.0.1\n" > /tmp/_mgr.ext
    openssl x509 -req -in /tmp/_mgr.csr -CA "$cd_certs/root-ca.pem" -CAkey "$cd_certs/root-ca.key" \
        -CAcreateserial -days 3650 -sha256 -extfile /tmp/_mgr.ext -out "$cd_certs/wazuh.manager.pem" 2>/dev/null || true
    cp -f "$cd_certs/root-ca.pem" "$cd_certs/root-ca-manager.pem"
    cp -f "$cd_certs/root-ca.key" "$cd_certs/root-ca-manager.key"
    rm -f /tmp/_mgr.csr /tmp/_mgr.ext "$cd_certs/root-ca.srl"
    # el34 동작 모델 = 전부 644(world-readable). 컨테이너 uid 무관하게 읽힘 (lab 인증서).
    $SUDO chmod 644 "$cd_certs"/*.pem "$cd_certs"/*-key.pem "$cd_certs"/*.key 2>/dev/null || true
    $SUDO chown -R "$REAL_USER:$REAL_USER" "$cd_certs" 2>/dev/null || true
    # 검증: manager 가 단일 root-ca 로 verify 되어야 함
    if ! openssl verify -CAfile "$cd_certs/root-ca.pem" "$cd_certs/wazuh.manager.pem" >/dev/null 2>&1; then
        echo "[el34] ERROR: 인증서 단일 CA 통일 실패 — wazuh.manager.pem 이 root-ca 로 verify 안 됨"; return 1
    fi
    echo "[el34] 인증서 준비 (단일 CA 통일, verify OK): $(ls "$cd_certs"/*.pem 2>/dev/null | wc -l) .pem"
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
    # 최초 setup: 웹 진입 고정 IP 를 사용자에게 1회 질의 → .env 에 고정(이후 up/재부팅 재사용)
    resolve_web_host_ip
    # 입력한 IP 를 유선 IF 에 netplan static 으로 고정(확인 후, 무선/0.0.0.0 은 자동 skip)
    netplan_static "$WEB_HOST_IP"
    echo "[el34] install 완료 — 다음: (docker 그룹 반영 위해 새 셸에서) ./el34.sh up"
}

# ───────────────────────────────────────────────── host network glue
cmd_net() { exec ./el34-net.sh; }

install_systemd() {
    # 호스트 IP alias 를 docker 기동 전에 보장 (재부팅 후 compose 바인딩 가능)
    $SUDO cp el34-hostip.service /etc/systemd/system/el34-hostip.service
    $SUDO cp el34-net.service /etc/systemd/system/el34-net.service
    $SUDO systemctl daemon-reload
    $SUDO systemctl enable el34-hostip >/dev/null 2>&1 || true
    $SUDO systemctl enable --now el34-net >/dev/null 2>&1 || true
    echo "[el34] el34-hostip/el34-net.service 설치·활성 (재부팅 후 IP alias + 체인 자동 보존)"
}

# ───────────────────────────────────────────────── sigma
cmd_sigma() { (cd sigma && SIEM_CONTAINER=el34-siem ./install-sigma.sh); }

# ───────────────────────────────────────────────── up (전체)
OVERLAY="-f docker-compose.yaml -f docker-compose.opencti.yml -f docker-compose.misp.yml -f docker-compose.sysmon.yml"
ENVF="--env-file .env --env-file .env.opencti --env-file .env.misp"

cmd_up() {
    # up 은 root 필요(인증서 권한 정규화 + el34-net iptables/sysctl + systemd). 비-root 면 sudo 재실행.
    if [ "$(id -u)" != 0 ]; then
        echo "[el34] up 은 root 권한 필요 — sudo 로 재실행합니다"
        exec sudo -E "$0" up
    fi
    command -v docker >/dev/null || { echo "[el34] Docker 없음 — 먼저 'sudo ./el34.sh install'"; exit 1; }
    ensure_env; ensure_ssh_keys; ensure_certs; ensure_misp_env; ensure_opencti_env
    resolve_web_host_ip  # install 에서 고정한 웹 진입 IP 사용(.env). 미설정이면 여기서 1회 질의.
    # compose 가 바인딩하는 호스트 IP(웹외부 WEB_HOST_IP / 내부GUI .145) 보장 — 없으면 core up 이
    # "cannot assign requested address" 로 실패. 실 NIC/DHCP IP 면 멱등 skip.
    WEB_HOST_IP="$WEB_HOST_IP" INT_HOST_IP="$INT_HOST_IP" ./el34-hostip.sh
    # el34-hostip 이 자가치유에 실패했는데도(IP 중복/무선/미탐지) 그대로 up 하면 fw 의
    # ${WEB_HOST_IP}:80 바인딩이 실패하고 fw 만 exit 255 → 웹 진입 포트 전체가 죽는다.
    # 실습장을 통째로 마비시키는 대신, 이번 기동만 0.0.0.0(모든 IF)로 낮춰 확실히 살린다.
    if [ -n "$WEB_HOST_IP" ] && [ "$WEB_HOST_IP" != "0.0.0.0" ] && \
       ! ip -4 addr show | grep -qw "$WEB_HOST_IP"; then
        echo "[el34] ⚠️  WEB_HOST_IP=$WEB_HOST_IP 가 이 호스트에 없음 — 이번 기동은 0.0.0.0(모든 인터페이스)로 대체"
        echo "        학생 hosts 는 VM 실제 IP($(detect_primary_ip || echo '?')) 로 매핑하세요."
        echo "        고정 IP 를 유지하려면 netplan static/DHCP 예약 후 './el34.sh up' 재실행."
        export WEB_HOST_IP=0.0.0.0   # compose 보간은 shell env > .env (.env 의 고정값은 보존)
    fi
    echo "[el34] === build (최초 ~수GB pull) ==="
    docker compose build
    echo "[el34] === core up ==="
    docker compose up -d
    ./el34-net.sh
    echo "[el34] === overlay up (opencti→misp 순서: redis=valkey 충돌 방지) ==="
    # MISP db(mysql) 첫부팅이 healthcheck 보다 느려 depends_on 이 일시 실패할 수 있음 → 재시도.
    for attempt in 1 2 3; do
        if docker compose $OVERLAY $ENVF up -d; then break; fi
        echo "[el34] overlay up 실패(시도 $attempt/3) — MISP db 첫부팅 등 일시적. 25s 후 재시도"
        sleep 25
    done
    ./el34-net.sh           # 오버레이가 core 재생성 → 글루 재적용
    install_systemd
    echo "[el34] === sigma 적재 ==="
    cmd_sigma || echo "[el34] WARN: sigma 적재 실패(나중에 ./el34.sh sigma)"
    # root 로 생성된 사용자-facing 파일을 원 사용자 소유로 환원 (이후 비-root 운영/down 가능하게)
    chown -R "$REAL_USER:$REAL_USER" .env .env.misp .env.opencti keys 2>/dev/null || true
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
