# el34 보안 실습 인프라 — 완전 재구축 프롬프트 (REBUILD PROMPT)

> ⚠️ **역사적 스냅샷(2026-06-03).** 이 문서는 el34 의 옛 설계(이전 버전) 상태를 기록한 재구축
> 프롬프트다. 이후 **재설계로 일부 구조가 바뀌었다** — 특히 HAProxy 제거(fw 는 L3 DNAT 만),
> ips masquerade 제거(출처 IP 보존), userland-proxy=false 등. **현재 정본은
> [`EL34-REDESIGN.md`](../EL34-REDESIGN.md) + 저장소 실제 소스(compose/entrypoint)** 다. 아래
> 내용 중 HAProxy·masquerade·컨테이너 수 등은 이 스냅샷 시점 기준이므로 그대로 신뢰하지 말 것.
>
> 작성일: 2026-06-03 · 대상 저장소: https://github.com/mrgrit/el34 · 기준 커밋: `46e1685`
>
> **이 문서의 목적**: 이 한 문서만으로 el34 프로젝트 전체를 빈 디렉토리에서 재구축할 수 있어야 한다.
> 아래 사양을 **빠짐없이** 구현하면 동일한 교육용 보안 실습 인프라가 재현된다. 모든 IP/포트/버전/
> 자격증명/취약점 목록/파일 경로는 정확한 값이며 임의로 변경하지 말 것.

---

## 0. 이 프롬프트의 사용 방법

당신은 시니어 보안 인프라 엔지니어다. 아래 명세를 받아 `el34/` 저장소를 처음부터 만든다.
- 언어/주석: 한국어 중심 (코드 식별자는 영어). 기존 톤(교육용, 친절한 안내 메시지) 유지.
- 모든 컨테이너는 단일 Linux VM(VMware Bridge/NAT) 위 Docker Compose 로 구동.
- "학생 신규 배포" 자동화가 핵심 — `bash el34.sh install && bash el34.sh up` 만으로 동작해야 함.
- 산출물: 섹션 3 의 파일 트리를 그대로 생성하고, 각 파일을 섹션별 사양대로 작성.

---

## 1. 프로젝트 개요

학생 PC 의 VMware VM 1대 안에 docker 컨테이너로 기업 보안 인프라를 재현한 **교육용 배포**.
- **4-tier 체인 토폴로지**: `ext → pipe → dmz → int` + 옵션 `user` zone.
- **강제 패킷 경로**: `external → fw(nftables L3/NAT) → ips(Suricata) → web(ModSecurity WAF) → endpoint`.
- 구성: 보안 인프라(fw/ips/web/siem 3종 Wazuh) + 취약 웹 7종 + 관리 포털 + AI 보안 에이전트(bastion).
- base 15 컨테이너 + 옵션(Windows 1, Ollama 1, sysmon-host 1, OpenCTI ~20, MISP 5).
- "300B" 라는 선행 프로젝트의 경량/분리 버전 (방화벽/IPS/WAF 를 별도 컨테이너로 분리한 점이 핵심 차별).

### 1.1 토폴로지 다이어그램

```
   ext 10.20.30.0/24       pipe 10.20.31.0/24      dmz 10.20.32.0/24                    int 10.20.40.0/24
   ┌─────────────────┐     ┌──────────────┐        ┌───────────────────────────┐       ┌─────────────────────┐
   │ attacker  .202  │     │              │        │ web         .80            │       │ juiceshop      .81  │
   │ bastion   .201  │───▶│  ips         │───────▶│ siem(mgr)   .100          │──────▶│ dvwa           .82  │
   │                 │    │  .2 ↔ dmz.1  │        │ wazuh-indexer .110        │       │ neobank        .83  │
   │                 │    │  ↕ user.1    │        │ wazuh-dashboard .120      │       │ govportal      .84  │
   └─────────────────┘     └──────────────┘        │ portal       .50          │       │ mediforum      .85  │
            │                      ▲               └───────────────────────────┘       │ adminconsole   .86  │
            ▼                      │                                                    │ aicompanion    .87  │
   ┌──────────────────────────────────┐                                                └─────────────────────┘
   │ fw  .1(ext) ↔ .1(pipe)          │   int 의 7 vuln 사이트는 외부 노출 X — web 의
   │ nftables L3 forward + HAProxy   │   Apache vhost reverse proxy 로만 도달.
   └──────────────────────────────────┘
                                                user 10.20.33.0/24  (옵션 --with-windows)
                                                ┌────────────────────────────────┐
                                                │ (옵션) win  .60  Windows 11     │  ← ips eth2 (10.20.33.1) GW
                                                │  Sysmon + Wazuh agent + OpenSSH │
                                                └────────────────────────────────┘
```

### 1.2 VM 권장 사양

| 등급 | CPU | RAM | Disk | 비고 |
|------|-----|-----|------|------|
| 최소 (Win 제외) | 4 vCPU | 6 GB | 100 GB | base 15 컨테이너 |
| 권장 (Win 제외) | 4 vCPU | 8 GB | 120 GB | + attacker 풀 도구 |
| 최소 (Win 포함) | 4 vCPU + VT-x | 16 GB | 150 GB | + win (tiny11 4G + 50G) |
| 권장 (Win 포함) | 6 vCPU + VT-x | 24 GB | 200 GB | 여유 학습 |

Windows 포함 시 `/dev/kvm` 필요 (BIOS VT-x/AMD-V + `kvm_intel`/`kvm_amd` 모듈 + `usermod -aG kvm $USER`).

---

## 2. 네트워크 설계 (가장 중요 — 정확히 재현)

### 2.1 Docker 네트워크 (6개, 모두 bridge)

| 이름 | subnet | gateway | 용도 |
|------|--------|---------|------|
| `el34-ext`  | 10.20.30.0/24 | 10.20.30.254 | attacker/bastion/fw(ext측) |
| `el34-pipe` | 10.20.31.0/24 | 10.20.31.254 | fw↔ips 전용 구간 |
| `el34-dmz`  | 10.20.32.0/24 | 10.20.32.254 | web/siem/indexer/dashboard/portal/**assessor(.55)**/**provisioner(.56)**/ips(dmz측) |
| `el34-int`  | 10.20.40.0/24 | 10.20.40.254 | 7 vuln 사이트 (외부 노출 X) |
| `el34-user` | 10.20.33.0/24 | 10.20.33.254 | Windows 등 사용자 PC, ips(user측 .1) 가 GW |
| `el34-wan`  | 10.20.20.0/24 | 10.20.20.254 | **(2026-06 추가)** attacker-ext('진짜 외부' 공격자, outsider). 내부 브리지와 격리 — NAT 로 호스트 LAN/공개 포트만 접근 |

compose 의 `networks:` 에서 `name:` 을 위 이름으로 고정하고 `ipam.config.subnet/gateway` 명시.
> `el34-wan` 은 `cmd_setup_forward` 의 inter-bridge 허용 목록(ext/pipe/dmz/int)에 **들어가지 않는다** → docker isolation 으로 내부 브리지와 차단. attacker-ext 는 fw/dmz/int 에 직접 못 닿고 VM 공개 포트로만 진입(외부 침입자 모델, §8.1).

### 2.2 고정 IP 할당표 (절대 변경 금지)

| 컨테이너 | ext | pipe | dmz | int | user | wan |
|----------|-----|------|-----|-----|------|-----|
| bastion | .201 | | | | | |
| attacker (insider) | .202 | | | | | |
| fw | .1 | .1 | | | | |
| ips | | .2 | .1 | | .1 | |
| web | | | .80 | .80 | | |
| siem (wazuh.manager) | | | .100 | | | |
| wazuh-indexer | | | .110 | | | |
| wazuh-dashboard | | | .120 | | | |
| portal | | | .50 | | | |
| **assessor** (2026-06) | | | .55 | | | |
| **provisioner** (옵션, 기본 OFF) | | | .56 | | | |
| **attacker-ext** (outsider, 2026-06) | | | | | | .202 |
| juiceshop | | | | .81 | | |
| dvwa | | | | .82 | | |
| neobank | | | | .83 | | |
| govportal | | | | .84 | | |
| mediforum | | | | .85 | | |
| adminconsole | | | | .86 | | |
| aicompanion | | | | .87 | | |
| (옵션) win | | | | | .60 | |
| (옵션) ollama | .220 | | | | | |
| (옵션) sysmon-host | .210 | | | | | |

> **assessor(.55)**: 읽기 전용 평가/모니터링 표면(`/assess`+`/activity`, X-API-Key). dmz alias `assessor`. 자세한 계약·type 은 **`ASSESSOR.md`**.
> **provisioner(.56)**: (옵션, 기본 OFF) 미션 룰 무장 write 서비스. profile `provisioner`, `SKIP_PROVISIONER=0` 으로만 기동.
> **attacker-ext(.202/wan)**: '진짜 외부' 공격자. 기존 attacker(ext)=내부 발판 insider 와 대비. profile `attacker-ext`(기본 ON, `SKIP_ATTACKER_EXT=1` 비활성).

fw 의 ext IP `.1` 에는 network alias `secu`, `el34-secu` 부여(legacy 4-VM 시대 호환). pipe IP `.1` 에도 동일 alias.
각 wazuh 서비스는 dmz alias 부여: indexer→`wazuh.indexer,wazuh-indexer`, siem→`siem,wazuh.manager,wazuh-manager`, dashboard→`wazuh.dashboard,wazuh-dashboard`.

### 2.3 패킷 체이닝 강제 메커니즘 (핵심 트릭)

Docker 기본 bridge 는 서로 다른 브리지 간 forward 를 막는다. 4-tier 체인을 살리기 위해:

1. **default route 강제**: 각 컨테이너 entrypoint 가 `DEFAULT_GW` 환경변수로 자기 default route 를 hop 으로 박는다.
   - bastion/attacker `DEFAULT_GW=10.20.30.1` (fw)
   - web `DEFAULT_GW=10.20.32.1` (ips)
   - **attacker-ext `DEFAULT_GW=""`** (빈값) → entrypoint 가 라우트 override 를 **건너뛰고** docker 기본 GW(wan .254) 유지. 그래서 내부 브리지로 못 가고 NAT 로 호스트 LAN(공개 포트)만 접근 = 외부 침입자. (attacker entrypoint 의 `${DEFAULT_GW-...}` 는 `:-` 가 아니라 `-` 라 빈값을 보존.)
   - fw 는 dmz/int(10.20.32.0/24, 10.20.40.0/24) 로 가는 route 를 ips(10.20.31.2) 경유로 추가.
   - ips 는 ext(10.20.30.0/24) 복귀 route 를 fw(10.20.31.1) 경유로 추가.
2. **ip_forward**: fw, ips 에 `sysctls: net.ipv4.ip_forward=1` + `cap_add: NET_ADMIN, NET_RAW`.
3. **ips MASQUERADE**: ips 가 dmz 로 나가는 트래픽(출발: ext/pipe/user)을 dmz 인터페이스로 SNAT (`nftables natel34` 테이블 POSTROUTING) → backend 가 ips 를 GW 로 인식, 역경로 불필요.
4. **호스트 iptables DOCKER-USER**: `el34.sh` 의 `cmd_setup_forward` 가 `up` 후 브리지 인터페이스 이름을 조회해 `DOCKER-USER` 체인에 `ext↔pipe`, `pipe↔dmz`, `dmz↔int` 양방향 ACCEPT 규칙을 삽입하고 끝에 `RETURN`.
5. **bridge-nf-call=0**: `cmd_check_kernel` 이 `br_netfilter` 로드 후 `net.bridge.bridge-nf-call-iptables=0` 설정 (host iptables FORWARD 가 브리지 트래픽에 개입하는 것을 막음). 영구화는 `/etc/sysctl.conf`.
6. **vm.max_map_count >= 262144**: wazuh-indexer(OpenSearch) 요구. `cmd_check_kernel` 이 설정 + 영구화.

### 2.4 외부 노출 포트 (fw HAProxy 가 유일 ingress)

| 포트(.env.example 기본) | 용도 | 매핑 |
|------|------|------|
| 80  (`PORT_HTTP`) | HTTP — 모든 vhost | fw:80 |
| 443 (`PORT_HTTPS`) | HTTPS self-signed | fw:443 |
| 2204 (`PORT_BASTION_SSH`) | bastion SSH 점프 | bastion:22 |
| 2202 (`PORT_ATTACKER_SSH`) | attacker SSH 직접 (insider) | attacker:22 |
| 2203 (`PORT_ATTACKER_EXT_SSH`) | **attacker-ext SSH (outsider, 2026-06)** | attacker-ext:22 |
| 9100 (`PORT_BASTION_API`) | Bastion API | fw:9100→bastion |
| 8000 (`PORT_PORTAL`) | 관리 포털(직접) | — (vhost portal.el34.lab 권장) |
| 5601 (`PORT_SIEM_DASH`) | SIEM lite UI(직접) | — |

vhost(Host 헤더, fw HAProxy 라우팅): 기존 `{juice,dvwa,neobank,govportal,mediforum,admin,ai,portal,siem,bastion}.el34.lab` 에 더해 **`assessor.el34.lab`(→10.20.32.55)**, **`provisioner.el34.lab`(→10.20.32.56, 옵션)** 추가.

> 운영자(개발) VM 의 실제 `.env` 는 충돌 회피용으로 `18080/18443/2284/2282/19100` 등을 쓰지만, **배포 기본값은 `.env.example` 의 80/443/2204/2202/9100**.

> **★ int(취약웹) 도달 메커니즘 — 포트포워딩 아님.** 외부에 열린 건 fw 의 `80/443`(+SSH/API)뿐이고, 그게 유일한 docker DNAT(포트포워딩)다. dvwa/juice 같은 **int 사이트는 절대 직접 포워딩하지 않는다** — `fw HAProxy(Host 헤더 분기) → ips(Suricata 인라인 검사) → web Apache(vhost + ModSecurity, mod_proxy) → int 백엔드` 의 **2겹 L7 리버스 프록시**로만 도달한다(web 이 dmz+int 양다리). 즉 모든 외부 요청이 IPS/WAF 검사를 강제로 거친다. attacker(insider)·attacker-ext(outsider) 둘 다 이 체인을 통과한다.

---

## 3. 저장소 파일 트리 (전부 생성)

```
el34/
├── el34.sh                      # 루트 오케스트레이터 (install/up/down/destroy/status/smoke/logs/windows/agents)
├── README.md                   # 학생/교사 가이드 (한국어)
├── WINDOWS-ENDPOINT.md         # Windows 옵션 상세 + KVM 트러블슈팅
├── .env.example                # 학생 복사 템플릿
├── .env.misp.example           # MISP overlay 템플릿
├── .gitignore
├── docker-compose.yaml         # base 15 컨테이너 (name: el34)
├── docker-compose.opencti.yml  # OpenCTI 7.x overlay
├── docker-compose.misp.yml     # MISP 5 컨테이너 overlay
├── docker-compose.ollama.yml   # Ollama overlay (ext .220)
├── docker-compose.sysmon.yml   # sysmon-for-linux host overlay (ext .210)
├── docker-compose.windows.yml  # Windows 11 endpoint overlay (user .60)
├── docker-compose.override.yaml# 운영자 0.110 전용 bastion API override
├── keys/                        # .gitkeep 만 추적 (id_rsa[.pub] 는 el34.sh 가 자동 생성, gitignore)
├── bastion/                     # SSH 점프 + Bastion AI API (Ubuntu)
│   ├── Dockerfile  entrypoint.sh  api.py(stub)
│   └── src/{apps/bastion, packages/bastion, packages/manager_ai, data/seed}
├── attacker/                    # pentest 도구 (Dockerfile entrypoint.sh motd)
├── fw/                          # nftables + HAProxy (Dockerfile entrypoint.sh nftables.conf haproxy.cfg)
├── ips/                         # Suricata + Wazuh agent (Dockerfile entrypoint.sh suricata-local.rules)
├── web/                         # Apache + ModSecurity (Dockerfile entrypoint.sh wazuh-agent.conf.append vhosts/ landing/)
├── siem/                        # Wazuh manager 커스텀 (Dockerfile + cont-init.d 스크립트 + 디코더/룰 xml)
├── wazuh-config/                # 인증서 생성 + indexer/manager/dashboard yml + certs/
├── portal/                      # FastAPI 관리 대시보드 (Dockerfile main.py requirements.txt templates/)
├── agent/                       # Manager+SubAgent 레이어 (setup-agents.sh subagent.py)
├── sysmon/                      # sysmon-for-linux (Dockerfile config.xml init-sysmon.sh init-sysmon.service)
├── win-oem/                     # install.bat (Windows OEM 무인설치)
├── secuops-easy-deploy/         # 특강 GUI 3종 배포 (deploy_all.sh fix_modsec.py patch_haproxy.py *.baseline README.md)
└── vuln-sites/                  # 5 커스텀 Flask 취약 웹 (neobank govportal mediforum adminconsole aicompanion)
```

---

## 4. 루트 오케스트레이터 `el34.sh`

bash, `set -euo pipefail`, 시작 시 `cd "$(dirname "$(readlink -f "$0")")"`. 서브커맨드 dispatch:
`install | up [--with-windows] | down | destroy | status | smoke | logs <svc> | agents | windows {up|down|destroy|status|logs} | help`.

### 4.1 헬퍼 함수
- `ensure_env`: `.env` 없으면 `.env.example` 복사.
- `ensure_ssh_keys`: `keys/` 생성, `keys/id_rsa` 없으면 `ssh-keygen -t ed25519 -f keys/id_rsa -N "" -C el34-bastion@auto`. 권한 600/644. **학생 환경마다 다른 키** (gitignore). 6개 컨테이너(bastion/attacker/fw/ips/web/siem)가 `./keys:/keys:ro` 마운트 → bastion 의 ccc 가 개인키 보유, 나머지는 pub 을 authorized_keys 로 받아 password 없는 ProxyJump.
- `ensure_misp_env`: `.env.misp` 없으면 `.env.misp.example` 복사 후 `BASE_URL=https://<VM_IP>:8443`, `MYSQL_PASSWORD`/`MYSQL_ROOT_PASSWORD`=`openssl rand -hex 16`, `CORE_HTTP_PORT=8880`, `CORE_HTTPS_PORT=8443`, `DISABLE_IPV6=true` 주입 (fw HAProxy 80/443 충돌 회피).
- `ensure_opencti_env`: `.env.opencti` 없으면 생성. `OPENCTI_ADMIN_TOKEN`/connector ID 들=`uuidgen`, `OPENCTI_ENCRYPTION_KEY`=`openssl rand -base64 32`, MINIO/RABBITMQ 자격증명=uuidgen, `OPENCTI_BASE_URL=http://<VM_IP>:8080`, `ELASTIC_MEMORY_SIZE=1G`. (모든 connector UUID 목록은 섹션 11.1.)
- `vm_ip`: `ip -4 -o addr` 중 사설대역(192.168/10./172.16-31) 에서 `10.20.30.` 제외 첫 IP.

### 4.2 `cmd_install` (Debian/Ubuntu 자동설치)
1. `sudo`/`apt-get` 존재 확인 (없으면 안내 후 종료).
2. `apt-get update` → 헬퍼 설치: `ca-certificates curl gnupg lsb-release git jq sshpass net-tools iproute2 dnsutils`.
3. Docker 없으면 공식 repo(`download.docker.com/linux/$ID`) 키 등록 후 `docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin` 설치, `systemctl enable --now docker`, `usermod -aG docker $USER`.
4. **Docker daemon DNS 박제**: `/etc/docker/daemon.json` 에 `"dns":["8.8.8.8","1.1.1.1"]` (jq merge, 기존 백업) → `systemctl restart docker`. (VM 에서 docker.io 해석 실패 방지.)
5. 검증 출력 + docker 그룹 미반영 시 `newgrp docker` 안내.

### 4.3 `cmd_up [--with-windows]`
순서: `cmd_check_docker` → `cmd_check_network`(registry-1.docker.io, github.com DNS+HTTPS 사전검사) → `cmd_check_kernel`(max_map_count, bridge-nf-call) → `ensure_env`/`ensure_ssh_keys`/`ensure_opencti_env`/`ensure_misp_env` → (--with-windows 시 `cmd_check_kvm`).
- **overlay 합성**: `COMPOSE_FILES="-f docker-compose.yaml"`, ENV `--env-file .env`. 다음 overlay 를 파일 존재 + SKIP 변수 미설정 시 추가:
  - OpenCTI: `SKIP_OPENCTI=0` → `-f docker-compose.opencti.yml --env-file .env.opencti`
  - MISP: `SKIP_MISP=0` → `-f docker-compose.misp.yml --env-file .env.misp`
  - sysmon: `SKIP_SYSMON=0` → `-f docker-compose.sysmon.yml`
  - Ollama: `SKIP_OLLAMA=0` → `-f docker-compose.ollama.yml`
- `docker compose $COMPOSE_FILES build && up -d` → `sleep 3` → `cmd_setup_forward` → `cmd_status`.
- `SKIP_AGENTS=0` 면 `agent/setup-agents.sh` 실행 (Manager+SubAgent).
- `--with-windows` 면 `docker compose -f docker-compose.windows.yml up -d` → `cmd_win_route_fix`.
- `SKIP_SECUOPS_EASY=0` (기본) 면 `cmd_secuops_easy_deploy` (fw/ips/web ready 대기 후 `secuops-easy-deploy/deploy_all.sh`).

### 4.4 기타 커맨드
- `cmd_setup_forward`: 2.3-④ 의 DOCKER-USER 규칙 삽입 (브리지 이름은 `docker network inspect` 의 `com.docker.network.bridge.name` 또는 `br-<id12>`).
- `cmd_win_route_fix`: win 컨테이너 default route 를 docker bridge(.254)→`10.20.33.1`(ips) 로 교체 (컨테이너 재시작마다 재적용).
- `cmd_check_kvm`: `/dev/kvm` 존재·rw 권한·가용 RAM(5G+) 검사.
- `cmd_down`: windows compose down + base down (볼륨 보존). `cmd_destroy`: `down -v --rmi local` + windows `down -v`.
- `cmd_status`: 컨테이너 표 + 브라우저 접속 안내 + hosts 라인 + SSH ProxyJump 예시 출력.
- `cmd_smoke`: ① 외부 포트(landing, bastion API) ② vhost reverse proxy(Host 헤더로 juice/dvwa/.../siem/bastion HTTP code) ③ 컨테이너 헬스 ④ Wazuh: `wazuh-control status`(6+ daemon), `agent_control -l`(3+ agent), `alerts.json` 라인수, indexer `_cluster/health`(green/yellow), dashboard `:5601` ⑤ bastion SSH(sshpass). HTTP 200/30x/401/403/404 면 OK.
- `cmd_logs <svc>`: `docker compose logs -f --tail=100`.

---

## 5. 환경 파일

### 5.1 `.env.example` (학생 복사 기본값)
```
LLM_BASE_URL=
LLM_MODEL=gemma3:4b
SSH_USER=ccc
SSH_PASS=ccc
PORT_HTTP=80
PORT_HTTPS=443
PORT_BASTION_SSH=2204
PORT_ATTACKER_SSH=2202
PORT_PORTAL=8000
PORT_SIEM_DASH=5601
PORT_BASTION_API=9100
API_KEY=ccc-api-key-2026
```
(추가로 compose 가 참조: `AICOMPANION_LLM_BACKEND=mock`, `LLM_MANAGER_MODEL`, `LLM_SUBAGENT_MODEL`.)

### 5.2 `.gitignore`
`.env`, `*.log`, `__pycache__/`, `*.pyc`, `node_modules/`, `.idea/`, `.vscode/`, `docker-compose.yaml.bak-*`, `keys/id_rsa`, `keys/id_rsa.pub`, `.env.opencti`, `.env.misp`, `win-storage/`, `win-shared/`. (`keys/.gitkeep` 만 추적.)

---

## 6. `docker-compose.yaml` (base 15 컨테이너)

`name: el34`. 섹션 2.2 IP 표, 섹션 2.1 네트워크, 아래 볼륨/환경을 그대로 구현.

**서비스별 핵심**:
- **bastion**: build `bastion/Dockerfile`, ext .201, port `${PORT_BASTION_SSH:-2204}:22`, `cap_add:[NET_ADMIN]`. env: `SSH_USER/SSH_PASS/API_KEY`, `LLM_BASE_URL=${LLM_BASE_URL:-http://192.168.0.109:11434}`, `LLM_MANAGER_MODEL=${LLM_MANAGER_MODEL}`, `LLM_SUBAGENT_MODEL=${LLM_SUBAGENT_MODEL}`(fallback 없음 — 미설정시 startup 실패로 즉시 인지), `DEFAULT_GW=10.20.30.1`. `extra_hosts`: 모든 `*.el34.lab → 10.20.30.1`(fw HAProxy). volumes: `bastion-data:/var/lib/bastion`, `bastion-ssh-host:/var/lib/bastion/ssh-host-keys`, `/var/run/docker.sock:ro`, `./keys:/keys:ro`.
- **attacker**: build `attacker/Dockerfile`, ext .202, port `${PORT_ATTACKER_SSH:-2202}:22`, `cap_add:[NET_ADMIN]`, `DEFAULT_GW=10.20.30.1`, `extra_hosts` 동일, volumes `attacker-home:/home/ccc`, `attacker-ssh-host`, `./keys:ro`.
- **fw**: build `fw/Dockerfile`, ext .1(+alias secu,el34-secu) / pipe .1(+alias). ports `80:80`, `443:443`, `9100:9100`. `cap_add:[NET_ADMIN,NET_RAW]`, `sysctls: net.ipv4.ip_forward=1`. env: `WAZUH_MANAGER=10.20.32.100`, `IPS_PIPE_IP=10.20.31.2`. `./keys:ro`.
- **ips**: build `ips/Dockerfile`, pipe .2 / dmz .1 / user .1. `cap_add:[NET_ADMIN,NET_RAW]`, ip_forward=1. env `WAZUH_MANAGER`, `FW_PIPE_IP=10.20.31.1`. volume `ips-suricata-logs:/var/log/suricata`, `./keys:ro`. `depends_on:[fw]`.
- **web**: build `web/Dockerfile`, dmz .80 / int .80. `cap_add:[NET_ADMIN]`, env `WAZUH_MANAGER`, `DEFAULT_GW=10.20.32.1`. volume `web-apache-logs:/var/log/apache2`, `./keys:ro`. `depends_on`: ips + 7 vuln.
- **wazuh-indexer**: image `wazuh/wazuh-indexer:4.10.0`, dmz .110. `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`, ulimits memlock -1, nofile 65536. 마운트: certs(root-ca.pem, wazuh.indexer-key/.pem, admin[-key].pem), `wazuh_indexer.yml→opensearch.yml`, `internal_users.yml`. 볼륨 `wazuh-indexer-data`.
- **siem**: build `siem/Dockerfile`, image tag `el34-siem:custom`, hostname `wazuh.manager`, dmz .100. `depends_on:[wazuh-indexer]`. env: `INDEXER_URL=https://wazuh.indexer:9200`, `INDEXER_USERNAME=admin`, `INDEXER_PASSWORD=SecretPassword`, `FILEBEAT_SSL_VERIFICATION_MODE=full`, SSL_* 경로, `API_USERNAME=wazuh-wui`, `API_PASSWORD=MyS3cr37P450r.*-`. ulimits memlock -1/nofile 655360. 볼륨: `wazuh-manager-etc/-logs/-queue/-var`, manager 인증서, `./keys:ro`. **주의**: `api.yaml` bind mount 금지(host uid 소유→rbac.db 생성 실패→crash loop). rate-limit 은 cont-init 스크립트가 주입.
- **wazuh-dashboard**: image `wazuh/wazuh-dashboard:4.10.0`, dmz .120, `depends_on:[wazuh-indexer,siem]`. env INDEXER admin/SecretPassword, `WAZUH_API_URL=https://wazuh.manager`, dashboard kibanaserver/kibanaserver, API wazuh-wui. 마운트 dashboard 인증서 + `opensearch_dashboards.yml` + `wazuh.yml`.
- **portal**: build `portal/Dockerfile`, dmz .50. 마운트(ro): docker.sock, `ips-suricata-logs:/data/suricata-logs`, `web-apache-logs:/data/apache-logs`, `bastion-data:/data/bastion-data`, `wazuh-manager-logs:/data/wazuh`. env `BASTION_API_URL=http://10.20.30.201:9100`, `BASTION_API_KEY=${API_KEY:-ccc-api-key-2026}`. `depends_on:[siem,web]`.
- **juiceshop**: `bkimminich/juice-shop:latest`, int .81.
- **dvwa**: `vulnerables/web-dvwa:latest`, int .82.
- **neobank/govportal/mediforum/adminconsole/aicompanion**: build `./vuln-sites/<name>`, int .83–.87, env `PORT=3001..3005`. aicompanion 추가 env: `LLM_BACKEND=${AICOMPANION_LLM_BACKEND:-mock}`, `OLLAMA_URL=${LLM_BASE_URL:-}`, `OLLAMA_MODEL=${LLM_MODEL:-gemma3:4b}`.

**volumes**: bastion-data, ips-suricata-logs, web-apache-logs, wazuh-indexer-data, wazuh-manager-etc/-logs/-queue/-var, attacker-home, bastion-ssh-host, attacker-ssh-host.

---

## 7. 보안 인프라 컨테이너 사양

공통 패턴(fw/ips/web/bastion/attacker): base `ubuntu:22.04`, `openssh-server`+`sudo`, ccc 사용자(`ccc:ccc`, NOPASSWD sudo), PermitRootLogin no/PasswordAuthentication yes, `/keys/id_rsa.pub` → ccc authorized_keys, entrypoint 가 default route(`DEFAULT_GW`) 설정 후 `sshd -D` foreground. fw/ips/web 는 `wazuh-agent=4.10.1-1` 설치(WAZUH_MANAGER=10.20.32.100), `osquery` 설치(W07).

### 7.1 fw (방화벽 — ext↔pipe edge router)
- 패키지: nftables, ipset, iptables, haproxy, tcpdump, conntrack, jq, osquery, wazuh-agent=4.10.1-1.
- entrypoint: ip_forward, dmz/int route via `IPS_PIPE_IP`(10.20.31.2), self-signed cert(`CN=*.el34.lab,O=el34,C=KR`,730d) → `/etc/haproxy/certs/server.pem`, nftables 적용, haproxy 기동, wazuh-agent enroll, sshd.
- **nftables.conf**: `inet six_filter`(INPUT: 22/icmp/established accept; FORWARD: established accept, 기본 accept; OUTPUT accept) + `ip six_nat`(PREROUTING/POSTROUTING placeholder, Docker NAT 보존).
- **haproxy.cfg**: global maxconn 4096 + syslog → `10.20.32.100:514`(de-NAT client IP 복원). frontend `http_in`(:80) Host 헤더 라우팅: `siem.el34.lab→dashboard(10.20.32.120:5601 ssl-verify none)`, `portal.el34.lab→portal(10.20.32.50:8000)`, `bastion.el34.lab→bastion(10.20.30.201:9100)`, 기본→`waf(10.20.32.80:80)`. frontend :443 TLS 종단 후 동일 라우팅(기본→waf_tls 10.20.32.80:443). frontend :9100 → bastion passthrough. (+ `fw-gui/ips-gui/waf-gui` ACL+backend → 각 컨테이너 :8080, **base config 에 내장**. 과거엔 patch_haproxy.py 로 런타임 주입했으나 anchor 불일치로 실패하던 것을 base 로 이전.)

### 7.2 ips (Suricata IPS — pipe↔dmz↔user)
- 패키지: suricata, suricata-update, nftables, tcpdump, jq, osquery, wazuh-agent=4.10.1-1.
- entrypoint: ext 복귀 route via `FW_PIPE_IP`(10.20.31.1), **natel34 테이블 POSTROUTING masquerade**(출발 10.20.30.0/24, 10.20.31.0/24, 10.20.33.0/24 → dmz 인터페이스), Suricata af-packet 듀얼(pipe+dmz) 기동, eve.json(json, stats 비활성-필드 256 초과 방지), wazuh-agent(eve.json json + syslog), sshd.
- **suricata-local.rules** (sid 1000001~1000005): ① UNION+SELECT SQLi ② `<script` XSS ③ User-Agent `sqlmap` ④ `../` path traversal ⑤ SYN flags threshold 30/10s nmap 스캔.

### 7.3 web (Apache + ModSecurity WAF)
- 패키지: apache2, libapache2-mod-security2, modsecurity-crs(OWASP CRS), ssl-cert, osquery, wazuh-agent=4.10.1-1. 모듈: proxy, proxy_http, proxy_wstunnel, headers, ssl, rewrite, security2.
- ModSecurity: `SecRuleEngine On`(단 juice.el34.lab vhost 는 `DetectionOnly` — W02/W03 학습), `SecAuditEngine RelevantOnly`, `SecAuditLog /var/log/apache2/modsec_audit.log`, JSON 포맷, parts ABCFHZ.
- self-signed cert `*.el34.lab` → `/etc/apache2/ssl/`. landing DocumentRoot `/var/www/landing/`.
- **vhosts/** (파일명 = 우선순위): `000-landing`(el34.lab→landing), `010-juice`(juice.el34.lab→juiceshop:3000, /socket.io WS, DetectionOnly), `020-dvwa`(→dvwa:80), `030-neobank`(→neobank:3001), `040-govportal`(→govportal:3002), `050-mediforum`(→mediforum:3003), `060-admin`(admin.el34.lab→adminconsole:3004), `070-ai`(ai.el34.lab→aicompanion:3005), `080-portal`(portal.el34.lab→portal:8000, ModSec off), `090-siem`(siem.el34.lab→wazuh-dashboard:5601 HTTPS SSLProxyEngine verify none), `100-bastion`(bastion.el34.lab→bastion:9100). 모든 vhost ProxyPreserveHost On + 개별 access/error 로그.
- **wazuh-agent.conf.append**: access.log(apache), error.log(apache), modsec_audit.log(json), landing/juice access 로그 localfile 추가.

### 7.4 siem (Wazuh manager 커스텀)
- base `wazuh/wazuh-manager:4.10.0` (RHEL 계열 → `yum install openssh-server openssh-clients sudo passwd hostname iproute procps-ng jq`). ccc 사용자(wazuh group 미가입, NOPASSWD sudo). `/opt/subagent.py` 포함.
- **cont-init.d 스크립트** (Wazuh s6 init 순서):
  - `95-api-rate-limit.sh`: api.yaml 에 `access: {max_request_per_minute:5000, max_login_attempts:50, block_time:30}` 주입 (기본 300 부족 → 429).
  - `95-haproxy-denat.sh`: `haproxy-denat-decoder.xml`→decoders/, `haproxy-denat-rules.xml`→rules/ 복사(매 기동).
  - `96-bastion-audit-rules.sh`: `bastion-audit-decoder.xml`/`bastion-audit-rules.xml` 복사 + ossec.conf 에 `<remote><connection>syslog</connection><port>514</port><protocol>udp</protocol><allowed-ips>10.20.0.0/16</allowed-ips></remote>` 추가.
  - `97-deploy-ssh-key.sh`: `/keys/id_rsa.pub`→ccc authorized_keys.
  - `98-start-subagent.sh`: `CCC_ROLE=siem python3 /opt/subagent.py` (:8002).
  - `99-start-sshd.sh`: sshd 백그라운드.
- **디코더/룰**:
  - `bastion-audit-decoder.xml`: `bastion-audit `(JSON_Decoder: course/user_prompt/step_order/duration_ms/outcome) + `bastion-lifecycle `(stage/seq/request_id/event/skill/attempt/target/success/score).
  - `bastion-audit-rules.xml`: 100200(L3 모든 audit), 100201(L5 60s+ slow), 100202(L7 fail), 100203(L4 self-correction), 100204(L10 위험 config 변경: drop counter/add rule/MASQUERADE/reverse shell/backdoor), 100210~100218(lifecycle: request/stage/lookup/skill_start/skill_result/self_verify/step_retry/completed).
  - `haproxy-denat-decoder.xml`: prematch ` http_in `, regex 로 de-NAT 원본 srcip 추출.
  - `haproxy-denat-rules.xml`: 100250(L3 access), 100251(L6 웹공격: UNION/SELECT/script/etc/passwd/sqlmap/../).
- 입력: 1514/tcp(agent: ips/web/[win]), 514/udp(syslog: fw HAProxy de-NAT, bastion/attacker rsyslog). alert viewer = wazuh-dashboard(5601).

### 7.5 wazuh-config/
- `generate.yaml`: `wazuh/wazuh-certs-generator:0.0.2` + `config/certs.yml`(nodes: indexer=wazuh.indexer, server=wazuh.manager, dashboard=wazuh.dashboard) → `./certs/` 1회 생성.
- `certs/`: root-ca[.key/.pem], root-ca-manager[.key/.pem], wazuh.{indexer,manager,dashboard}[-key].pem, admin[-key].pem.
- `wazuh_indexer.yml`(OpenSearch security 설정), `internal_users.yml`(admin/kibanaserver 해시), `wazuh.yml`(dashboard→manager API 연결), `opensearch_dashboards.yml`, `api.yaml`.

### 7.6 통합 로깅 패러다임 (학습 핵심)
| Source | 방식 | 경로 |
|--------|------|------|
| ips(Suricata) | Wazuh **agent** | eve.json+fast.log → siem:1514/tcp |
| web(Apache+ModSec) | Wazuh **agent** | access/error/modsec_audit → 1514/tcp |
| win(Sysmon, 옵션) | Wazuh **agent**(MSI) | EventChannel+Security → 1514/tcp |
| bastion(sshd) | **rsyslog** forward | auth.log → siem:514/udp |
| attacker(shell) | **rsyslog** forward | shell → 514/udp |

agent 패러다임 = 자체 binary 디코딩, syslog 패러다임 = raw forward + manager 디코딩.

---

## 8. bastion / attacker / portal 상세

### 8.1 attacker (insider) + attacker-ext (outsider, 2026-06)
**attacker** (ext .202): ubuntu:22.04 + pentest 도구 `nmap, hydra, sqlmap, nikto, ffuf`, nuclei, msfconsole, netcat, curl, python3, dnsutils. rsyslog → siem 514/udp. motd 배너. `extra_hosts` 로 `*.el34.lab→10.20.30.1`(fw). `DEFAULT_GW=10.20.30.1`. ccc/ccc. → **내부 발판 있는 침입자(insider)**: ext 브리지에서 fw 내부 IP·bastion 직접 접근 가능, 내부 이름(`dvwa.el34.lab→10.20.30.1`)으로 공격.

**attacker-ext** (wan .202, **동일 이미지/entrypoint 재사용**): profile `attacker-ext`(기본 ON, `SKIP_ATTACKER_EXT=1` 비활성). 차이점:
- `DEFAULT_GW=""` → 라우트 override 안 함, docker 기본 GW(wan .254) 유지. **`extra_hosts` 없음**(외부엔 내부 DNS 없음).
- wan 은 inter-bridge 허용 목록 밖 → **ext/dmz/int 직접 차단**. NAT 로 호스트 LAN 만: 자기 VM 공개 포트(`<VM_IP>:80/443/2204/2202/9100`) + 상대 VM 공개 포트로만 접근.
- → **'진짜 외부' 침입자(outsider)**: 공개 표면만 보고 `curl -H "Host: dvwa.el34.lab" http://<VM_IP>/` 처럼 공격. solo 도 duel(상대 VM 공격)과 **동일한 외부 진입 경로**가 됨.
- 동기: solo 에서 insider 가 내부 이름으로 치면 "VM 안에서 출발"이라 외부 공격답지 않음. outsider 를 둬서 insider/outsider 두 위협을 모두 실습. SSH 직접 `ssh -p 2203 ccc@<VM_IP>`.
- 한계(단일 VM): 컨테이너라 호스트 동거는 불가피 — 완전한 '외부 머신'은 duel 상대 VM. attacker-ext 는 단일 VM 안 최선 근사(내부 발판 0).

### 8.2 bastion (컨테이너 셸)
- Dockerfile(ubuntu:22.04): openssh-server, sudo, rsyslog, python3-pip, docker-ce-cli, osquery, geoip-bin, whois, auditd, jq, vim, tmux. pip: fastapi, uvicorn[standard], httpx, pydantic, pyyaml, pandas, numpy, scikit-learn. COPY `bastion/api.py`→`/opt/bastion-api/api.py`(stub), `bastion/src`→`/opt/ccc-src/`.
- entrypoint.sh: default route(`DEFAULT_GW`); KG seed 임포트(`/opt/ccc-src/data/seed/bastion_graph_seed.db`→`bastion_graph.db` 없을 때만 복사, audit seed 동일); ccc 사용자+ProxyJump `~/.ssh/config`(el34-fw/el34-attacker 직접, el34-ips/web/portal/siem 은 fw 경유); docker group GID 매칭; SSH host key 영구화(`/var/lib/bastion/ssh-host-keys`); rsyslog 전체→siem:514/udp + bastion-audit(LOG_LOCAL5)→`/var/log/bastion-audit.log`+forward; **API 기동 분기**: `LLM_BASE_URL` 설정 + `/opt/ccc-src/apps/bastion` 존재 → full Bastion(`uvicorn apps.bastion.api :9100`, PYTHONPATH `/opt/ccc-src:/opt/ccc-src/packages`), 아니면 stub(`/opt/bastion-api/api.py`, /health only); `sshd -D`.
- **stub api.py** (FastAPI, `API_KEY=ccc-api-key-2026`): `GET /health`(status/hostname/llm_configured), `GET /targets`(X-API-Key), `POST /exec`(화이트리스트 ping/uptime/hostname/.../curl http 만), `GET /skills`(정적 카탈로그).

### 8.3 bastion AI 에이전트 패키지 (`bastion/src/packages/bastion/`)
풀 버전은 **지식그래프(KG) 기반 자율 보안 LLM 에이전트** (Manager+SubAgent A2A 협업). pyproject `name=ccc-bastion v1.0.0`, deps httpx/pyyaml/fastapi/uvicorn/pydantic, scripts `bastion-api`/`bastion-tui`.
- **agent.py**: BastionAgent 3-stage(PLANNING→EXECUTING→VALIDATING). playbook 선택/multi-skill 선택/dynamic playbook 생성, NDJSON 이벤트 스트림, gpt-oss harmony 토큰 처리, 12-turn 히스토리+auto-compaction, 2회 self-correction.
- **skills.py**: 50+ skill(probe_host/scan_ports/check_suricata/configure_nftables/attack_simulate/prompt_fuzz/garak_probe/forensic_collect/history_anchor/shell/docker_manage/ollama_query…), 8 카테고리. `execute_skill` → SubAgent `POST /a2a/run_script`.
- **graph.py**: SQLite KG. 노드 Playbook/Experience/Skill/Error/Recovery/Concept/Insight/Narrative/Anchor/Asset/Mission/Vision/Goal/Strategy/KPI/Plan/Todo, FTS5 검색. **history.py**(L4: events/narratives/anchors/changelog, anchor 는 압축면역), **audit.py**(SHA-256 hash-chain append-only), **experience.py/compaction.py**(경험→insight 압축), **kg_context.py/kg_recorder.py/kg_metrics.py**(프롬프트 주입/기록/카운터), **asset_domain.py/work_domain.py**(자산 토폴로지 / 9-tier OKR), **rag.py**(BM25 키워드 인덱스), **prompt.py/playbook.py/verify.py/lab_verify.py/lookup.py**.
- **apps/bastion/api.py**: FastAPI :9100. 핵심 엔드포인트: `POST /chat`(NDJSON 스트림 planning/executing/validating), `POST /ask`, `POST /onboard`, `GET /health`, `/kg/health|/kg/audit|/kg/metrics`, `/skills`, `/playbooks`, `/assets`, `/evidence`, `/audit[/{id}|/_stats|/_verify-chain]`, `/graph/*`(stats/nodes/edges/node/search/lineage/delete/compact), `/history/*`(narratives/anchors/events/handoff/changelog/repeat-iocs), `/knowledge/concept`, `/assets/*`, `/architecture/{topology,flow}`, `/work/*`(mission/vision/goal/strategy/kpi/plan/todo/status/trace/dashboard), Ollama 호환 프록시 `/api/{generate,chat,tags,version}`.
- **seed DB**: `bastion_graph_seed.db`(~4.3MB, 397 노드/168 anchor), `bastion_audit_seed.db`(~1.7MB, 327 audit). 첫 기동 시에만 복사(학생 데이터 보존).

### 8.4 agent/ (Manager + SubAgent 레이어)
- **subagent.py**: 각 컨테이너(attacker/fw/ips/web/siem)에 배포되는 HTTP 워커 :8002. `GET /health`(status/hostname/role), `POST /a2a/run_script`(`{script,timeout}`→subprocess→`{exit_code,stdout(30KB),stderr(5KB)}`). SIGHUP 무시(detach 내성).
- **setup-agents.sh**: ①각 컨테이너에 subagent.py cp→`docker exec -d CCC_ROLE=<role> python3 /tmp/subagent.py`→/health 대기(멱등). ②Manager 준비: `github.com/mrgrit/bastion.git` clone(timeout 90s)→venv+pip(timeout 240s; 네트워크 실패 시 Manager skip, SubAgent·콘솔은 유지)→`.env` 생성(`LLM_BASE_URL`, `LLM_MANAGER_MODEL=gpt-oss:120b`, `LLM_SUBAGENT_MODEL=gemma3:4b`, VM IP 들, `BASTION_API_PORT=9200`, `BASTION_API_KEY=ccc-api-key-2026`). ③Manager 기동(nohup setsid :9200, /health 대기).
- **LLM 모델**: `LLM_BASE_URL`=Ollama 서버, `LLM_MANAGER_MODEL`=메인 지능(gpt-oss:120b 권장), `LLM_SUBAGENT_MODEL`=경량 스크립트 추출(gemma3:4b). 공격 코스는 `LLM_MANAGER_MODEL_UNSAFE`(derestricted) 사용 가능.

### 8.5 portal (FastAPI 관리 대시보드)
- Dockerfile python:3.12-slim + curl. requirements: `fastapi==0.115.6 uvicorn[standard]==0.34.0 jinja2==3.1.5 docker==7.1.0 httpx==0.28.1`. `uvicorn main:app --port 8000`.
- main.py: docker.sock(ro)로 컨테이너 상태, 마운트 로그(suricata eve.json / apache modsec_audit·error / bastion auth.log / wazuh) 파싱.
- 라우트/템플릿: `/`(dashboard), `/resources`, `/network`, `/logs`+`/logs/{name}/tail`, `/waf`(ModSec 30건+top rule), `/ids`(Suricata 30건+top signature+event count), `/audit`(SSH auth 50건), `/agent`(BASTION_API /health,/skills,/targets, X-API-Key), `/health`(JSON). 템플릿: base/dashboard/resources/network/logs/waf/ids/audit/agent.html.

---

## 9. 취약 웹 7종 (`vuln-sites/`)

juiceshop(`bkimminich/juice-shop:latest`, int .81, admin@juice-sh.op 추측), dvwa(`vulnerables/web-dvwa:latest`, int .82, admin/password) 는 외부 이미지. 나머지 5종은 커스텀 Flask.

**공통**: base `python:3.11-slim`, `EXPOSE 300X`, `ENV PORT=300X`, `CMD python app.py`. SQLite(`<name>.db`, `init_db()` 첫 기동 자동 시드). 각 디렉토리에 `seed/vulnerabilities.md`(정상모드 취약점), `seed-hard.md`(하드모드 5 체인) 포함 — 학습 가이드.

### 9.1 neobank (포트 3001 — 가상 은행, KRW)
- requirements: `flask>=2.3,<4`, `PyJWT>=2.8`, `requests>=2.31`. session secret 약함.
- 시드 계정: `admin@neobank.local/admin`(admin, 999M), `alice@example.com/alice123`, `bob@example.com/bobpassword`, `carol@example.com/qwerty`, `teller1@neobank.local/teller1`(teller).
- **30 취약점(V01–V30)** 요약: IDOR(/accounts/<id>, /transfer/<tid>/cancel), SQLi(/login, /search, /api/users/check), JWT(exp 없음·weak secret `neobank-supersecret-2024`·alg=none), 헤더 인증우회(X-Internal/X-Role), CSRF+race(/transfer), Stored/Reflected XSS, Path traversal(/statements?file=), Open redirect(/logout?next=), SSRF(/loan/check?url=), 약한 reset 토큰(md5(time)[:8]), 사용자 열거, PII 노출(/api/admin/users: ssn/phone/api_key), Mass assignment(/api/profile/update), Pickle RCE(/api/session/restore), XXE(/api/transfers/import), Cmd injection(/api/receipts/render), LFI(/render?template=), CORS `*`+credentials, verbose error, 기본자격, outdated deps(/version). 템플릿: base/index/login/dashboard/account/transfer/search.html.

### 9.2 govportal (포트 3002 — 가상 정부 민원)
- requirements: `flask`, `PyJWT`. session `gov-flask-weak`, JWT_SECRET `gov-shared-secret-2023`, SAML_HMAC_KEY `gov-saml-key`.
- 시드: `admin@gov.local/admin`(authority 99), `kim@gmail.com/kim2024`, `lee@naver.com/password`, `park@daum.net/minsu1234`(clerk), `jung@example.com/jung01`(officer). admin console PIN `1234`.
- **25 취약점**: SAML 서명 미검증/JIT/issuer 미검증(/saml/login), SQLi(/login), JWT weak/none, 예측가능 cert 번호, X-Authority-Level 헤더 신뢰, 파일업로드 무검증(.php/.jsp)+path traversal(/apply), CSRF, Stored XSS(clerk_queue), audit 변조(/api/audit/clear), XXE(/api/applications/import), IDOR(/applications/<id>), 강제 승인, path traversal 다운로드(/cert/download?path=), PII CSV(/api/citizens/export.csv), X-Forwarded-For 신뢰(/api/admin/citizens), mass assignment(role/authority), 기본 PIN, SSN 변경, verbose error, Apache 2.4.49 배너(CVE-2021-41773), 보안헤더 누락. 템플릿: base/index/login/saml_login/dashboard/apply/app_detail/clerk_queue/admin_pin/admin_console.html.

### 9.3 mediforum (포트 3003 — 의료 익명 커뮤니티)
- requirements: `flask`. session `mediforum-not-secret-2026`(예측가능 sid counter sess-1001…). ADMIN_TOKEN `MEDIFORUM-ADMIN-2026-DEV`(X-Admin-Token 우회).
- 시드: `admin@medi.kr/admin123`, `dr.kim@medi.kr/doctor123`, `dr.lee@medi.kr/doctor123`, `alice@user.kr/alice123`, `bob@user.kr/bob123`, `carol@user.kr/carol123`.
- **22 취약점**: Stored XSS(글/댓글/bio/DM), CSRF, PII bulk(/api/users), 의료기록 노출(/api/medical-records 무인증), IDOR, broken auth(/api/admin/*), API key URL, 쿠키 insecure, CORS `*`, 예측 세션, 이메일 열거, 검색 PII, Mass assignment, SVG XSS 업로드(/profile/avatar), open redirect(/go?to=), verbose error, 하드코딩 토큰. 템플릿: base/index/login/register/post_new/post_detail/profile/profile_edit/dm/search.html.

### 9.4 adminconsole (포트 3004 — DevOps 패널, RCE 집중)
- Dockerfile 추가 apt: `iputils-ping dnsutils whois git curl`(cmd injection 실증용). requirements: `flask`, `PyYAML>=6.0`. session `ADMINCONSOLE-INSECURE-2026`, SHARED_SECRET `ac-shared-secret-2026`.
- 시드: `admin/admin`, `ops1/ops1pass`, `dev/devpass`, `auditor/auditorpw`. 시드 secrets(AWS key/DB url/SSH key/git token).
- **28 취약점**: cmd injection(/tools ping·dig·whois), SSRF(fetch·/api/webhook/test), git option inject RCE(git_clone), eval RCE(calc), pickle RCE(/api/jobs/import), path traversal(/files/read), LFI+log poison(/logs/view), 약한 reset 토큰(md5(email+date)[:12])+열거+만료없음, 기본자격, JWT alg=none, IDOR secrets(/api/secrets/<id>), YAML unsafe_load(/api/jobs/import.yaml), 하드코딩 secret, verbose error, 무인증 user list, CSRF+mass assignment(/api/users/update), Stored XSS(/notes), 업로드 무검증, XXE(/api/import.xml), HTTP smuggling 표면, open redirect(/sso/return), 토큰 URL. 템플릿: base/index/login/forgot/reset/tools/notes.html.

### 9.5 aicompanion (포트 3005 — LLM 챗봇, OWASP LLM Top 10)
- requirements: `flask`. `LLM_BACKEND=mock`(키워드 기반) 기본, `ollama` 시 `OLLAMA_URL/api/generate` 호출(gemma3:4b). session `AICOMPANION-INSECURE-2026`. SYSTEM_PROMPT 에 master override `ACME-OVERRIDE-2026` + admin@acme.local. 하드코딩 `OPENAI_API_KEY=sk-fake-PROD-AI-COMPANION-9b2f7c1d8a`.
- 시드: `admin/admin`, `alice/alice123`, `bob/bob123`. RAG 시드 문서에 의도적 PII(SSN/AWS키/급여).
- **25 취약점**(LLM01-10 + OWASP): 시스템 프롬프트 override(/api/chat {"system"}), 간접 인젝션(RAG poison /api/rag/add 무인증), jailbreak, 프롬프트 유출(/api/debug/prompt), 데이터셋 유출(/api/dataset), KB PII(/kb), insecure output(innerHTML), tool abuse(/api/tool/exec_python eval, /api/tool/http_get SSRF, /api/tool/chain), excessive agency(/api/tool/update_user), model theft(/api/model/export), 하드코딩 키, 토큰 URL, path traversal(/api/rag/load?file=), stored memory inject(/profile), DoS(rate limit 없음), pickle(/api/conv/import), CSRF+mass assign role(/profile), 기본자격, CORS `*`. 템플릿: base/index/login/chat/profile/kb.html.

---

## 10. 접속 모델 / 자격증명

### 10.1 학생 PC hosts 파일 (각 줄 IP 로 시작 — wrap 주의)
```
<VM_IP>  el34.lab juice.el34.lab dvwa.el34.lab neobank.el34.lab govportal.el34.lab mediforum.el34.lab admin.el34.lab ai.el34.lab portal.el34.lab
<VM_IP>  siem.el34.lab bastion.el34.lab assessor.el34.lab fw-gui.el34.lab ips-gui.el34.lab waf-gui.el34.lab
```
> ⚠️ 한 줄로 길게 넣다가 줄바꿈되면 둘째 줄(siem 이후)에 IP 가 빠져 그 항목만 미해석 → "안 열림"
> (juice~portal 만 열리고 siem/콘솔이 안 열리는 전형적 증상). 위처럼 각 줄을 IP 로 시작하면 안전.
브라우저: `http://<service>.el34.lab/` (web Apache vhost reverse proxy). 직접 포트(`:8000` portal, `:5601` siem, `:9100/health` bastion)는 ModSec 우회 — 학습 비교용.

### 10.2 SSH ProxyJump
`~/.ssh/config`: `el34-bastion`(port 2204 ccc), `el34-attacker`(port 2202 ccc), `el34-fw el34-ips el34-web el34-siem el34-portal el34-win`(ProxyJump el34-bastion). bastion 내부 alias: `ssh fw`(10.20.30.1), `ssh ips`(10.20.31.2), `ssh web`(10.20.32.80), `ssh siem`(10.20.32.100), `ssh attacker`(10.20.30.202), `ssh win`(10.20.33.60).

### 10.3 자격증명 정리
| 시스템 | 계정 |
|--------|------|
| 모든 컨테이너 SSH | `ccc / ccc` (.env SSH_USER/SSH_PASS) |
| Bastion API | header `X-API-Key: ccc-api-key-2026` |
| Wazuh indexer/manager | `admin / SecretPassword` (운영시 변경) |
| Wazuh API | `wazuh-wui / MyS3cr37P450r.*-` |
| dashboard server | `kibanaserver / kibanaserver` |
| DVWA | `admin / password` |
| 5 커스텀 사이트 | 섹션 9 시드 계정 / seed/vulnerabilities.md |

---

## 11. 옵션 오버레이

### 11.1 OpenCTI (`docker-compose.opencti.yml`)
OpenCTI 7.x ~20 컨테이너: redis(redis:8.6.1), elasticsearch(8.19.12), minio, rabbitmq(4.2-management), opencti/platform, worker(x3), xtm-composer, connector 10종(export stix/csv/txt, import stix/document/yara, analysis, external-reference, opencti, mitre), rsa-key-generator. 포트 8080. env 는 `ensure_opencti_env` 가 `.env.opencti` 자동 생성(섹션 4.1). `SKIP_OPENCTI=1` 로 비활성. (자원 적은 학생용.)

### 11.2 MISP (`docker-compose.misp.yml` + `.env.misp.example`)
5 컨테이너: misp-core, misp-modules(헬스체크 start_period 120s/retries 30 — VM 의존성 느림), db(mariadb:10.11), redis(valkey/valkey:7.2), mail(ghcr.io/egos-tech/smtp:1.1.3) + 옵션 misp-guard. 포트 8880/8443(fw 80/443 충돌 회피). CORE_TAG v2.5.37, MODULES_TAG v3.0.7. `ensure_misp_env` 자동. `SKIP_MISP=1`.

### 11.3 Ollama (`docker-compose.ollama.yml`)
`ollama/ollama:latest`, ext .220, port 11434, volume ollama-data. CPU inference(느림). `SKIP_OLLAMA=1`.

### 11.4 sysmon-host (`docker-compose.sysmon.yml` + `sysmon/`)
W11 sysmon-for-linux(systemd+eBPF). build `sysmon/Dockerfile`(jrei/systemd-ubuntu:22.04 + sysmonforlinux + openssh). `privileged:true`, `cap_add:[SYS_ADMIN,BPF,NET_ADMIN]`, `cgroup:host`, 마운트 `/sys/fs/cgroup`(rw)·`/sys/kernel/debug`(rw)·`/lib/modules`(ro)·`./keys`(ro). ext .210, SSH `${PORT_SYSMON_SSH:-2210}`. config.xml(SwiftOnSecurity 류), init-sysmon.sh(sysmon -i + key + sshd). `SKIP_SYSMON=1`.

### 11.5 Windows 11 (`docker-compose.windows.yml` + `win-oem/install.bat`)
`dockurr/windows`, el34-win, user .60. env VERSION tiny11/RAM_SIZE 4G/CPU_CORES 2/DISK_SIZE 48G/USERNAME ccc/PASSWORD ccc. devices `/dev/kvm`,`/dev/net/tun`. 포트 8006(VNC)/3389(RDP). 마운트 win-storage:/storage, win-oem:/oem, win-shared:/data. network el34-user(external).
**install.bat (OEM 무인설치)**: ① 정적 라우팅(ext/pipe/dmz/int → 10.20.33.1 ips) ② Sysmon64 + SwiftOnSecurity config ③ Wazuh agent 4.10.0 MSI(WAZUH_MANAGER=10.20.32.100, name el34-win) + agent-auth + Sysmon eventchannel localfile 주입 ④ OpenSSH Win64 v9.8.1.0p1(기본셸 PowerShell, 방화벽 22 허용, sshd auto) ⑤ hosts `*.el34.lab→10.20.32.80` ⑥ ICMP 허용 + Wazuh 재기동 ⑦ 완료마커 `\\host.lan\Data\OEM_DONE.txt`. 첫 부팅 30-60분. `cmd_win_route_fix` 가 default route 를 ips 로 교체.

### 11.6 override (`docker-compose.override.yaml`)
운영자 0.110 전용. bastion 에 port 9200 + `/home/ccc/bastion`·`/home/ccc/data` 마운트(KG DB). 학생 배포 미적용.

---

## 12. secuops-easy 특강 GUI (`secuops-easy-deploy/`)

방화벽/IPS/WAF 를 브라우저 GUI 로 학습. **이미지 내장 → 컨테이너 기동 시 자동 실행**(별도 배포 단계·네트워크 불필요).
- **3 GUI**(Python stdlib only): `secuops-easy-deploy/gui/{nft_edu_gui→fw, suricata_edu_gui→ips, modsec_edu_gui→web}` (upstream `mrgrit/*_edu_gui` 를 vendoring). 각 Dockerfile 이 `/opt/<gui>/` 로 COPY, entrypoint 가 `:8080` 자동 기동 → fw-gui/ips-gui/waf-gui.el34.lab.
- **HAProxy 라우트는 `fw/haproxy.cfg`(base)에 내장**: ACL `is_fw_gui/is_ips_gui/is_waf_gui` + backend(fw 127.0.0.1:8080 / ips 10.20.31.2:8080 / web 10.20.32.80:8080, check 미사용). 런타임 patch/reload 없음.
- **deploy_all.sh** = 오프라인 검증/치유 보조(필수 아님): ① `fix_modsec.py`(멱등) ② `suricata_local.rules.baseline`(멱등) ③ GUI 가 :8080 미응답 시 vendored 소스로 재기동 ④ HAProxy 라우트 존재 확인(없을 때만 `patch_haproxy.py` backward-compat) ⑤ 콘솔 title 검증(랜딩 fallthrough 거짓 200 차단).
- **(과거 사고)** `patch_haproxy.py` anchor 가 `acl is_bastion `(1칸)인데 base 는 정렬상 2칸 → 패치 영구 실패 → 콘솔이 `default_backend`(랜딩)로 fallthrough(거짓 200). 라우트를 base 에 내장 + GUI 이미지화하여 근본 해결(2026-06).
- SIEM 연동: fw GUI→`/var/log/nft_edu/events.log`(wazuh agent tail).

---

## 13. 빌드 / 기동 시퀀스 (검증 기준)

```bash
git clone https://github.com/mrgrit/el34 && cd el34
bash el34.sh install        # docker+compose+helpers (Debian/Ubuntu), docker group 추가
newgrp docker              # 또는 새 터미널
cp .env.example .env       # (el34.sh 가 자동으로도 함)
bash el34.sh up                  # base 15 + overlay + secuops-easy GUI (첫 빌드 20-30분, ~15GB)
bash el34.sh up --with-windows   # + Windows tiny11 (KVM, 첫 부팅 +30-60분)
bash el34.sh smoke          # 헬스 + Wazuh agent 등록 검증
bash el34.sh status         # VM_IP/포트/SSH 안내
```

**e2e 검증(공격→탐지)**:
```bash
ssh el34-attacker
nmap -sT -p 22,80 web
curl -A 'sqlmap/1.7' http://web/                 # WAF 403
curl "http://web/?q=' UNION SELECT 1,2,3--"      # SQLi 403 + Suricata 1000001
exit; ssh el34-siem
sudo tail -20 /var/ossec/logs/alerts/alerts.json | jq '.rule.description, .agent.name'
```

**Wazuh 검증**: `wazuh-control status`(8 daemon), `agent_control -l`(ips/web[/win]), `_cluster/health`(green/yellow).

---

## 14. 버전 / 상수 부록 (정확히 일치시킬 것)

| 항목 | 값 |
|------|-----|
| 인프라 base image | `ubuntu:22.04` (fw/ips/web/bastion/attacker) |
| Wazuh manager | `wazuh/wazuh-manager:4.10.0` (RHEL 계열, yum) |
| Wazuh indexer/dashboard | `wazuh/wazuh-indexer:4.10.0`, `wazuh/wazuh-dashboard:4.10.0` |
| Wazuh agent (Linux) | `wazuh-agent=4.10.1-1` (apt pin) |
| Wazuh agent (Windows) | `wazuh-agent-4.10.0-1.msi` |
| Wazuh certs generator | `wazuh/wazuh-certs-generator:0.0.2` |
| vuln-sites base | `python:3.11-slim` (포트 3001-3005) |
| portal base | `python:3.12-slim`, FastAPI 0.115.6 / uvicorn 0.34.0 / jinja2 3.1.5 / docker 7.1.0 / httpx 0.28.1 |
| juiceshop / dvwa | `bkimminich/juice-shop:latest`, `vulnerables/web-dvwa:latest` |
| Ollama | `ollama/ollama:latest`, gemma3:4b 기본 |
| Windows | `dockurr/windows` VERSION tiny11, OpenSSH v9.8.1.0p1 |
| OpenCTI deps | redis 8.6.1, elasticsearch 8.19.12, rabbitmq 4.2-management |
| MISP deps | mariadb 10.11, valkey 7.2, smtp 1.1.3, CORE_TAG v2.5.37, MODULES_TAG v3.0.7 |
| API_KEY | `ccc-api-key-2026` |
| Wazuh admin | `admin / SecretPassword`, API `wazuh-wui / MyS3cr37P450r.*-` |
| LLM 모델 | Manager `gpt-oss:120b`, SubAgent `gemma3:4b` |
| 도메인 | `*.el34.lab` (self-signed `CN=*.el34.lab,O=el34,C=KR` 730일) |

**불변식(반드시 지킬 것)**: ① 패킷은 fw→ips→web 강제 경유 ② int 7 사이트는 외부 비노출(web vhost 만 도달) ③ Wazuh 2 패러다임(agent: ips/web/win, syslog: bastion/attacker) ④ 학생마다 SSH 키/MISP/OpenCTI 자격 자동 생성(gitignore) ⑤ siem 컨테이너 api.yaml bind mount 금지 ⑥ overlay 는 SKIP_* 로 토글, base 15 컨테이너는 항상 단독 동작 ⑦ **Bastion·토폴로지·취약웹·Wazuh 코어 무변경**(Assessor 레이어는 별개 서비스로만 얹음).

---

## 15. 평가/모니터링 레이어 + 외부 공격자 (2026-06 추가 · 다른 에이전트 참고)

> 중앙 플랫폼 **tubewar/CC** 가 학생 VM 을 읽기 전용으로 pull(채점·모니터링)하고 cross-infra 듀얼(VM↔VM)을 운영한다. el34 측에 추가된 표면·컨테이너 요약. **상세·계약·예시는 저장소 `ASSESSOR.md` 가 정본.**

### 15.1 Assessor (읽기 전용 표면, 기본 ON)
- 컨테이너 `el34-assessor`(dmz **10.20.32.55**, profile `assessor`, `SKIP_ASSESSOR=1` 비활성), `python:3.12-slim`+FastAPI. read-only 마운트: docker.sock·wazuh-manager-logs·ips-suricata-logs·web-apache-logs. 인증 `X-API-Key`(`API_KEY`, 기본 `ccc-api-key-2026`). 외부: `assessor.el34.lab`.
- 두 표면(둘 다 raw 만 반환, **Cohort/과목/학년 태깅은 tubewar 책임 — el34 엔 없음**):
  - **`POST /assess`** 채점: check type `file_exists/file_contains/file_hash/process_running/port_listening/log_contains/wazuh_alert/fim_change/command_ran`. 호스트 단언은 **osquery 우선 + docker.sock exec 폴백**, 보안신호는 Wazuh `alerts.json`(+옵션 indexer). 고정 템플릿+화이트리스트로만 합성(주입 면역, 부작용 0).
  - **`POST /activity`** 모니터링: `commands/fim/alerts/services` 활동 스트림(since_sec/limit/want/filter).
- `GET /health`(무인증): `{status,hostname,version,wazuh_reachable,surfaces,supported_types,targets}`.

### 15.2 정적 Wazuh 수집 보강 (cohort-free, 모든 학생 동일)
- **FIM(syscheck, realtime+report_changes+whodata)**: web(apache/modsec confs), fw(/etc/nftables.conf,/etc/haproxy), ips(/etc/suricata), 각 /home/ccc. (`web/wazuh-agent.conf.append` + fw/ips entrypoint 가 `el34-assessor-collection` 블록을 ossec.conf 에 멱등 주입.)
- **명령 로깅**: 전 컨테이너 `/etc/profile.d/el34-cmdlog.sh` 의 PROMPT_COMMAND → `CMDEL34 ...` 라인. attacker/bastion=rsyslog→siem:514, web/fw/ips=`/var/log/el34-cmd.log` localfile. manager `cmdlog` decoder/rules(`siem/cmdlog-*.xml`, cont-init `94-cmdlog-rules`) → alerts.json. **OS_Regex 주의: decoder 의 `\.`=임의문자(PCRE 와 반대), program_name parent+필드 child 구조.**
  - auditd execve(2번째 명령원)는 **비특권 컨테이너에서 audit netlink 불가**(CAP 줘도 Operation not permitted)라 미채택 — PROMPT 가 단일 경로(`/activity` commands 는 auditd 형태도 forward-compat 파싱).

### 15.3 (옵션) 룰 무장 provisioner (write, 기본 OFF)
- 컨테이너 `el34-provisioner`(dmz **10.20.32.56**, profile `provisioner`, **`SKIP_PROVISIONER=1` 기본**). read-only 원칙의 유일 예외. `provisioner.el34.lab`.
- `POST /provision-rule {template,params}` / `POST /revoke-rule {sid}`. named 템플릿 화이트리스트(`alert_command_pattern`/`alert_fim_path`)만, sid **110000–119999**, manager 전용 파일 `zz-el34-provisioned-rules.xml`(마지막 로드, if_sid 해소) 하나만 write. **반영 전 `wazuh-analysisd -t` 검증→실패 시 롤백**(나쁜 룰이 manager 못 깨뜨림). tubewar 가 미션 시작 무장·종료 회수.
- 미션별 동적 탐지 3경로: ① check-spec 온디맨드(권장,추가 0) ② 학생 작성 룰(file_contains+wazuh_alert) ③ 이 provisioner(옵션). 기본은 ①.

### 15.4 cross-infra 듀얼 (VM↔VM) — insider/outsider
- 외부 표면(=VM↔VM 공격 표면)은 새 노출 없이 기존대로: fw `80/443/9100` + SSH `2204/2202/2203`. int(취약웹)은 비노출, web vhost 리버스 프록시(§2.4 ★)로만 도달 → cross-VM 공격도 상대 IPS/WAF 검사 강제.
- **attacker(ext)=insider**(내부 발판), **attacker-ext(wan)=outsider**(공개 포트로만). duel 상대 VM = 완전한 외부. tubewar 는 A 의 attacker(-ext)가 B 의 `<B_IP>:80`(Host 헤더)·`:2204` 등을 치게 한다.

---

*이 문서는 2026-06-03 기준 실행 중인 인프라(컨테이너 18종 + 인프라 직접 검증)와 저장소 전체 소스를 정밀 분석해 작성됨. 누락 없이 이 사양대로 구현하면 el34 전체가 재현된다. 2026-06 추가분(Assessor/provisioner/attacker-ext)은 §15 + `ASSESSOR.md` 참조.*
