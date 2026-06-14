# 6v6 — CCC 인프라 단일 VM Docker 버전 (+ 7 취약 웹 + 통합 SIEM)

학생 PC 의 **VMware Bridge VM 1대 안에** docker 컨테이너로 CCC 의 보안 인프라를
그대로 올리고 **취약 웹 7개 + 관리 포털 + Wazuh manager/indexer/dashboard** 까지 추가한
교육용 배포. **4-tier 토폴로지** (ext / pipe / dmz / int) 로 실제 기업망과 동형.

```
   ext 10.20.30.0/24       pipe 10.20.31.0/24      dmz 10.20.32.0/24                    int 10.20.40.0/24
   ┌─────────────────┐     ┌──────────────┐        ┌───────────────────────────┐       ┌─────────────────────┐
   │ 6v6-attacker .202│    │              │        │ 6v6-web         .80       │       │ juiceshop      .81  │
   │ 6v6-bastion  .201│───▶│  6v6-ips     │───────▶│ 6v6-siem(mgr)   .100      │──────▶│ dvwa           .82  │
   │                  │    │  .2 ↔ dmz.1 │        │ 6v6-wazuh-indexer .110    │       │ neobank        .83  │
   │                  │    │  ↕ user.1   │        │ 6v6-wazuh-dashboard .120  │       │ govportal      .84  │
   └─────────────────┘     └──────────────┘        │ 6v6-portal       .50      │       │ mediforum      .85  │
            │                      ▲               └───────────────────────────┘       │ adminconsole   .86  │
            ▼                      │                                                    │ aicompanion    .87  │
   ┌──────────────────────────────────┐                       │                        └─────────────────────┘
   │ 6v6-fw   .1 (ext) ↔ .1 (pipe)   │                        │ web 의 Apache vhost 만 int 로 reverse proxy
   │ nftables L3 forward + DNAT      │                        │ (학생/공격자는 int 직접 접근 불가)
   └──────────────────────────────────┘                       ▼
                                                       (7 vuln sites 외부 노출 X)

                                                user 10.20.33.0/24  (옵션 --with-windows)
                                                ┌────────────────────────────────┐
                                                │ (옵션) 6v6-win  .60  Windows 11 │  ← ips eth2 (10.20.33.1)
                                                │  Sysmon + Wazuh agent + OpenSSH │     이 user 구역의 게이트웨이
                                                └────────────────────────────────┘
   트래픽 흐름: attacker → fw(L3/NAT) → ips(L7 sniff/Suricata) → dmz(web/siem) | user(win) → [web]만 int(vuln)
```

> **Windows 엔드포인트 (옵션, `--with-windows`)** 는 별도 `user` 구역 `10.20.33.60` 에 자리한다.
> `ips` 가 user 구역의 게이트웨이(eth2, 10.20.33.1)를 겸하므로 PC 의 모든 트래픽은 IPS 검사선
> 위에 올라온다. Wazuh agent 가 dmz 의 wazuh manager(10.20.32.100) 로 Sysmon eventchannel 을
> 보낸다 (user→ips→dmz 경유). 외부 공격자 → Windows 트래픽도 `fw → ips → user` 정책 검사를
> 거쳐 도달.

## 통합 로그 (Wazuh — agent + syslog 두 패러다임)

| Source | 방식 | 로그 | 경로 |
|--------|------|------|------|
| **6v6-ips** (Suricata) | Wazuh **agent** | eve.json + fast.log | siem:1514/tcp |
| **6v6-web** (Apache+ModSec) | Wazuh **agent** | access/error/modsec_audit | siem:1514/tcp |
| **6v6-win** (Sysmon, 옵션) | Wazuh **agent** (Windows MSI) | Sysmon EventChannel + Security | siem:1514/tcp |
| **6v6-bastion** (sshd) | **rsyslog** forward | auth.log + system | siem:514/udp |
| **6v6-attacker** (shell) | **rsyslog** forward | shell + system | siem:514/udp |

학습 포인트: Suricata · ModSecurity · Sysmon 은 **agent 패러다임** (자체 binary 가 디코딩까지),
bastion + attacker 는 **syslog 패러다임** (rsyslog 가 raw forward, manager 가 디코딩).

## VM 권장 사양

| 등급 | CPU | RAM | Disk | 비고 |
|------|-----|-----|------|------|
| 최소 (Windows 제외) | 4 vCPU | 6 GB | 100 GB | 13 컨테이너 (`bash 6v6.sh up`) |
| 권장 (Windows 제외) | 4 vCPU | 8 GB | 120 GB | + attacker 풀 도구 |
| 최소 (Windows 포함) | 4 vCPU + VT-x | 16 GB | 150 GB | + `6v6-win` (Windows 11 tiny11 + 4G + 50G) |
| 권장 (Windows 포함) | 6 vCPU + VT-x | 24 GB | 200 GB | 여유롭게 학습 진행 |

> Windows 포함 시 추가 요구: **`/dev/kvm` 접근 가능** (VT-x/AMD-V BIOS 활성 + `kvm_intel`
> 또는 `kvm_amd` 커널 모듈 로드). 학생 user 가 `kvm` 그룹 멤버여야 함 (`sudo usermod -aG kvm $USER`).
> `bash 6v6.sh up --with-windows` 가 시작 전에 자동 검사한다.

## 빠른 시작 (리눅스만 설치된 새 VM 기준)

```bash
git clone https://github.com/mrgrit/6v6
cd 6v6

# 1) Docker + 도구 자동 설치 (Ubuntu 22.04 / Debian 12)
bash 6v6.sh install         # docker, docker compose plugin, git, jq, sshpass, dnsutils
                             # 'docker' 그룹에 사용자 추가 후 종료

# 2) 새 터미널 열거나
newgrp docker

# 3) 환경 설정
cp .env.example .env        # LLM_BASE_URL 만 옵션 (aicompanion 은 mock 으로 동작 가능)

# 4) 기동 — 둘 중 하나 선택
bash 6v6.sh up                     # (A) 13 컨테이너만 (첫 빌드 8~12분, Windows 제외)
bash 6v6.sh up --with-windows      # (B) 14 컨테이너 (+ Windows tiny11; 추가 30-60분 첫 부팅)

bash 6v6.sh smoke           # 헬스 + Wazuh agent 등록 검증
bash 6v6.sh status          # 외부 접속 안내 (VM_IP / 포트 / SSH 명령)
```

> **Windows 옵션 (B)** 은 KVM 가속 필수 — `bash 6v6.sh up --with-windows` 가 먼저
> `/dev/kvm` 존재·권한·가용 RAM 을 검사하고 실패 시 친절히 안내한다.
> Windows 만 따로 끄려면: `bash 6v6.sh windows down`. 다시 켜기: `bash 6v6.sh windows up`.

`6v6.sh install` 이 자동 설치하는 항목:
- Docker Engine + CLI + containerd
- docker-buildx-plugin + docker-compose-plugin
- git, curl, jq, sshpass, net-tools, iproute2, dnsutils, gnupg, lsb-release
- `docker` group 에 현재 사용자 추가 (재로그인 또는 `newgrp docker` 필요)

> 자동 설치는 **Debian/Ubuntu 계열만 지원**. RHEL/CentOS/Arch 등은 `docker-ce` +
> `docker-compose-plugin` 을 각 배포판 패키지 매니저로 직접 설치 후 `bash 6v6.sh up` 사용.

## 외부 노출 포트

| 포트 | 용도 |
|------|------|
| 80 | HTTP — 7 vhost (랜딩 + 7 취약 웹) |
| 443 | HTTPS (self-signed) |
| 2204 | bastion SSH (점프 호스트) |
| 2202 | attacker SSH (insider — 내부 발판) |
| 2203 | attacker-ext SSH (outsider — 공개 포트로만, 2026-06) |
| 8000 | 관리 포털 |
| 5601 | SIEM lite UI (Wazuh 알림 viewer) |
| 9100 | Bastion API |

## 컨테이너 구성 (base 15개 + 옵션 Windows 1)

| 컨테이너 | Zone / IP | 역할 |
|----------|-----------|------|
| 6v6-bastion | ext 10.20.30.201 | SSH 점프 + Bastion API + rsyslog forward |
| 6v6-attacker | ext 10.20.30.202 | 공격자(**insider** — 내부 발판) nmap/hydra/sqlmap/nikto/ffuf/nuclei + rsyslog |
| 6v6-attacker-ext | wan 10.20.20.202 | 공격자(**outsider** — 공개 포트로만, 2026-06) `SKIP_ATTACKER_EXT=1` 로 비활성 |
| **6v6-fw** | ext .1 ↔ pipe .1 | **방화벽** — nftables L3 forward + DNAT + HAProxy |
| **6v6-ips** | pipe .2 ↔ dmz .1 | **IPS** — Suricata 인라인 sniff + **Wazuh agent** |
| 6v6-web | dmz .80 ↔ int .80 | Apache + ModSecurity + 7 vhost + **Wazuh agent** |
| 6v6-siem | dmz 10.20.32.100 | **Wazuh manager** (1514 agent / 514 syslog 입력) + alert viewer |
| 6v6-wazuh-indexer | dmz 10.20.32.110 | OpenSearch (Wazuh 알림 색인) |
| 6v6-wazuh-dashboard | dmz 10.20.32.120 | Wazuh Dashboard UI (5601) |
| 6v6-portal | dmz 10.20.32.50 | 관리 대시보드 (FastAPI + HTMX) |
| 6v6-assessor | dmz 10.20.32.55 | **읽기 전용 평가 수집** (CC/tubewar 채점용, profile `assessor`, `SKIP_ASSESSOR=1` 로 생략) |
| 6v6-juiceshop | int 10.20.40.81 | OWASP Juice Shop (web vhost 만 도달) |
| 6v6-dvwa | int 10.20.40.82 | DVWA |
| 6v6-neobank | int 10.20.40.83 | NeoBank (Flask, 30 취약점) |
| 6v6-govportal | int 10.20.40.84 | GovPortal (Flask, 25 취약점) |
| 6v6-mediforum | int 10.20.40.85 | MediForum (Flask) |
| 6v6-adminconsole | int 10.20.40.86 | AdminConsole (Flask, RCE/XXE) |
| 6v6-aicompanion | int 10.20.40.87 | AICompanion (LLM 취약점, mock 가능) |

> int(10.20.40.0/24) 의 7 vuln 사이트는 **외부 노출 X** — `web` 의 Apache vhost reverse
> proxy 로만 도달. attacker → fw → ips → web → vuln 의 강제 경유.
>
> **int 도달 메커니즘(포트포워딩 아님):** 외부에 열린 docker DNAT(포트포워딩)는 fw 의 `80/443`
> (+SSH/API)뿐. int 사이트는 **절대 직접 포워딩하지 않고**, `fw HAProxy(Host 헤더 분기) →
> ips(Suricata) → web Apache(vhost+ModSecurity, mod_proxy) → int 백엔드` 의 **2겹 L7 리버스
> 프록시**로만 열린다(web 이 dmz+int 양다리). 그래서 모든 외부 요청이 IPS/WAF 검사를 강제로 거친다.
>
> **공격자 두 종류:** `6v6-attacker`(ext)=**insider**(내부 발판, 내부 이름으로 공격),
> `6v6-attacker-ext`(wan)=**outsider**(내부 브리지 차단, `<VM_IP>` 공개 포트로만 — solo 도 duel 과
> 동일한 외부 경로). 둘 다 위 리버스 프록시 체인을 거쳐 탐지된다.

### 옵션 — Windows 엔드포인트 (16번째 컨테이너)

| 컨테이너 | Zone / IP | 역할 |
|----------|-----------|------|
| 6v6-win | user 10.20.33.60 | Windows 11 tiny11 사용자 PC — Sysmon + Wazuh agent + OpenSSH 자동계측 |

> Windows 는 별도 **user** 구역에 있고, `ips` 가 user 구역의 게이트웨이(eth2 10.20.33.1)를
> 겸하여 user↔dmz 트래픽도 IPS 검사선 위에 올라옵니다. Wazuh agent 는 dmz 의 wazuh manager
> (10.20.32.100) 로 user→ips→dmz 경유로 enroll. 공격자가 Windows 를 노려도 트래픽은
> `attacker(ext) → fw → ips → win(user)` 정책 경유 — base 와 동일한 방어선 적용.

배포 방법 (두 가지 동등):

```bash
# (1) 본 스택 가동 시 같이 띄움 — 추천
bash 6v6.sh up --with-windows

# (2) 본 스택 가동 후 따로 — 학습 중간에 켜고 싶을 때
bash 6v6.sh windows up     # = docker compose -f docker-compose.windows.yml up -d
bash 6v6.sh windows status # 부팅 진행 / OEM 완료 여부 (win-shared/OEM_DONE.txt)
bash 6v6.sh windows down   # Windows 만 중단 (본 스택 유지)
bash 6v6.sh windows logs   # 부팅·OEM 진행 로그 follow
```

자세히는 `WINDOWS-ENDPOINT.md`. 첫 부팅 시 30-60분 (Windows ISO 다운로드 + OEM 자동설치).
RAM 4G 추가 + 디스크 50G+ 필요. KVM 가능한 호스트만 (`up --with-windows` 가 사전검사).

## 학생 PC 접속 — 시스템별 가이드

전제: VM IP 는 `bash 6v6.sh status` 로 확인. 아래 `<VM_IP>` 자리에 실제 IP 대체.

### 1. 브라우저 (학생 PC)

먼저 학생 PC 의 hosts 파일에 1줄 추가:
- 윈도우: `C:\Windows\System32\drivers\etc\hosts` (관리자 권한 메모장)
- 리눅스/맥: `/etc/hosts` (sudo)

```
<VM_IP>  6v6.lab juice.6v6.lab dvwa.6v6.lab neobank.6v6.lab govportal.6v6.lab mediforum.6v6.lab admin.6v6.lab ai.6v6.lab portal.6v6.lab
<VM_IP>  siem.6v6.lab bastion.6v6.lab assessor.6v6.lab fw-gui.6v6.lab ips-gui.6v6.lab waf-gui.6v6.lab
```

> ⚠️ **두 줄로 나눠 각 줄을 IP 로 시작**하세요. 한 줄로 길게 넣다가 에디터에서 줄바꿈되면
> 둘째 줄(siem·콘솔)에 IP 가 빠져 그 항목만 "안 열림"이 됩니다 — `juice`~`portal` 은 되는데
> `siem`/`*-gui` 만 안 열리면 99% 이 문제입니다. (이름은 파일에 다 있어 보여도 IP 가 안 붙은 것.)
> 확인: 클라이언트에서 `ping siem.6v6.lab` → VM IP 가 나와야 정상.

그 후 브라우저 — **모두 동일 패턴 `<service>.6v6.lab` 으로 접근** (web 의 Apache vhost 가 reverse proxy):

| URL | 대상 | 비고 |
|-----|------|------|
| `http://6v6.lab/` 또는 `http://<VM_IP>/` | **랜딩 페이지** | 모든 사이트 링크 |
| `http://juice.6v6.lab/` | OWASP Juice Shop | 가입 자유 / `admin@juice-sh.op` 비밀번호 추측 |
| `http://dvwa.6v6.lab/` | DVWA | `admin / password` |
| `http://neobank.6v6.lab/` | NeoBank (가상 은행) | 30 취약점 |
| `http://govportal.6v6.lab/` | GovPortal (가상 정부) | 25 취약점 |
| `http://mediforum.6v6.lab/` | MediForum (가상 의료) | 게시판 + 업로드 |
| `http://admin.6v6.lab/` | AdminConsole | RCE/XXE/SSRF/pickle |
| `http://ai.6v6.lab/` | AICompanion | OWASP LLM Top 10 (mock LLM) |
| `http://portal.6v6.lab/` | **관리 포털** | 컨테이너 / 네트워크 / 로그 / WAF / IDS / Audit / Agent |
| `http://siem.6v6.lab/` | **SIEM (Wazuh lite)** | 알림 + Top rule + level 분포 |
| `http://bastion.6v6.lab/health` | Bastion API | 헬스 체크 (웹 UI 없음 — `/health` 만) |
| `http://fw-gui.6v6.lab/` | **방화벽 콘솔** (nftables 교육 GUI) | secuops-easy 특강. fw HAProxy 경유 |
| `http://ips-gui.6v6.lab/` | **IPS 콘솔** (Suricata 교육 GUI) | secuops-easy 특강 |
| `http://waf-gui.6v6.lab/` | **WAF 콘솔** (ModSecurity 교육 GUI) | secuops-easy 특강 |

> **secuops-easy GUI 3종**(fw-gui/ips-gui/waf-gui)은 fw/ips/web **이미지에 내장**되어
> 각 컨테이너 entrypoint 가 :8080 으로 **자동 기동**하고, HAProxy 라우트도 base 설정에 포함된다.
> 따라서 `down→up`·재부팅 후 **GitHub clone 도, 런타임 패치도 없이** 즉시 열린다(네트워크 불필요).
> 점검: `bash 6v6.sh smoke` 의 "교육용 콘솔" 항목(콘솔 페이지 title 확인). 혹시 누락 시
> 오프라인 치유: `bash secuops-easy-deploy/deploy_all.sh`. (`SKIP_SECUOPS_EASY=1` 로 생략 가능.)

> **직접 포트 접근도 살아있음** (관리/디버그용): `http://<VM_IP>:8000/` (portal),
> `http://<VM_IP>:5601/` (siem), `http://<VM_IP>:9100/health` (bastion).
> 이 경로는 ModSecurity 검사를 거치지 않음 — 학습 비교용.

### 2. SSH (Bastion ProxyJump 모델)

학생 PC `~/.ssh/config` 에 1회 등록:

```ssh-config
Host 6v6-bastion
  HostName <VM_IP>
  Port 2204
  User ccc

Host 6v6-attacker
  HostName <VM_IP>
  Port 2202
  User ccc

Host 6v6-fw 6v6-ips 6v6-web 6v6-siem 6v6-portal 6v6-win
  ProxyJump 6v6-bastion
  User ccc
```

| 명령 | 대상 컨테이너 | 진입 경로 |
|------|--------------|----------|
| `ssh 6v6-bastion` | bastion (점프 호스트) | 직접 (port 2204) |
| `ssh 6v6-attacker` | attacker (pentest 도구) | 직접 (port 2202, 빠른 공격 진입) |
| `ssh 6v6-fw` | fw (nftables 방화벽 + HAProxy) | bastion 경유 자동 |
| `ssh 6v6-ips` | ips (Suricata + Wazuh agent) | bastion 경유 자동 |
| `ssh 6v6-web` | web (Apache + ModSec + Wazuh agent) | bastion 경유 자동 |
| `ssh 6v6-siem` | siem (Wazuh manager) | bastion 경유 자동 |
| `ssh 6v6-portal` | portal (관리 대시보드) | bastion 경유 자동 |
| `ssh 6v6-win` | Windows 11 (옵션, PowerShell 셸) | bastion 경유 자동 |

**bastion 안에 들어가서**는 alias 자동 등록되어 다음도 가능:
```bash
ssh fw         # 10.20.30.1   (방화벽 — ext 쪽 IP)
ssh ips        # 10.20.31.2   (IPS — pipe 쪽 IP)
ssh web        # 10.20.32.80  (web — dmz 쪽 IP)
ssh siem       # 10.20.32.100 (Wazuh manager)
ssh attacker   # 10.20.30.202
ssh win        # 10.20.33.60  (Windows, 옵션 user 구역 — PowerShell)
```

### 3. 컨테이너 직접 (VM 호스트에서, 디버그/관리)

```bash
docker exec -it 6v6-bastion bash       # bastion API 디버그
docker exec -it 6v6-fw bash            # nftables 룰 / HAProxy / fw 라우팅
docker exec -it 6v6-ips bash           # Suricata / Wazuh agent (eve.json)
docker exec -it 6v6-web bash           # Apache / ModSec / Wazuh agent
docker exec -it 6v6-siem bash          # Wazuh manager (analysisd/remoted/...)
docker exec -it 6v6-wazuh-indexer bash # OpenSearch
docker exec -it 6v6-wazuh-dashboard bash  # Wazuh Dashboard
docker exec -it 6v6-attacker bash      # pentest 도구
docker exec -it 6v6-portal bash        # FastAPI portal
docker exec -it 6v6-juiceshop sh       # JuiceShop (Node.js, Alpine)
docker exec -it 6v6-dvwa bash          # DVWA (PHP + MySQL)
docker exec -it 6v6-neobank bash       # NeoBank Flask
# (govportal / mediforum / adminconsole / aicompanion 동일 패턴)
# Windows (옵션): docker exec 으로는 곤란 — SSH 또는 http://<VM_IP>:8006 VNC 권장
```

### 4. 핵심 운영 명령

| 명령 | 의미 |
|------|------|
| `bash 6v6.sh status` | 외부 접속 정보 + 컨테이너 상태 (windows 포함) |
| `bash 6v6.sh smoke` | 외부 노출 포트 + Wazuh agent 등록 + SSH 헬스 |
| `bash 6v6.sh logs <svc>` | 컨테이너 로그 follow |
| `docker exec 6v6-siem /var/ossec/bin/wazuh-control status` | Wazuh manager 8 daemon 상태 |
| `docker exec 6v6-siem /var/ossec/bin/agent_control -l` | 등록된 agent (ips/web/[win] 보여야) |
| `docker exec 6v6-siem tail -20 /var/ossec/logs/alerts/alerts.json` | 최근 alert |
| `docker exec 6v6-fw  sudo nft list ruleset` | 방화벽 룰 (ext↔pipe forward + DNAT) |
| `docker exec 6v6-ips tail /var/log/suricata/eve.json` | Suricata 알림 (IPS 컨테이너) |
| `docker exec 6v6-web tail /var/log/apache2/modsec_audit.log` | ModSecurity 차단 로그 |

### 5. 빠른 e2e 테스트 — attacker 에서 SQLi 발사 → SIEM 알림 확인

```bash
# 학생 PC 에서 attacker 진입
ssh 6v6-attacker

# 안에서:
nmap -sT -p 22,80 web                              # 포트 스캔
curl -A 'sqlmap/1.7' http://web/                    # WAF 차단 확인 (HTTP 403)
curl "http://web/?q=' UNION SELECT 1,2,3--"         # SQLi (HTTP 403)
nikto -h http://web/                                # 종합 스캐너

# 발사 후 SIEM 의 alert 확인:
exit
ssh 6v6-siem
sudo tail -20 /var/ossec/logs/alerts/alerts.json | jq '.rule.description, .agent.name'
```

또는 portal 에서 시각적 확인:
- `http://<VM_IP>:8000/waf` — ModSec audit 이벤트
- `http://<VM_IP>:8000/ids` — Suricata alert
- `http://<VM_IP>:5601/` — Wazuh 통합 알림 (agent + syslog)

### 6. 비밀번호 / 인증 정보 정리

| 시스템 | 계정 |
|--------|------|
| 모든 컨테이너 SSH | `ccc / ccc` (`.env` 의 `SSH_USER` / `SSH_PASS`) |
| Bastion API | header `X-API-Key: ccc-api-key-2026` |
| Wazuh manager API (5601 lite UI 는 인증 없음) | `admin / SecretPassword` (실제 운영시 변경) |
| DVWA | `admin / password` |
| JuiceShop | 가입 자유, `admin@juice-sh.op` 의 비밀번호 추측 학습 |
| NeoBank / GovPortal / MediForum / AdminConsole | seed 폴더의 vulnerabilities.md 확인 |

## Wazuh 동작 검증

```bash
# 1) manager 의 8 daemon 확인
docker exec 6v6-siem /var/ossec/bin/wazuh-control status

# 2) 등록된 agent 목록 (ips, web — Windows 옵션 시 win 추가)
docker exec 6v6-siem /var/ossec/bin/agent_control -l

# 3) 최근 alert (Suricata + ModSec [+ Sysmon] 통합)
docker exec 6v6-siem tail -20 /var/ossec/logs/alerts/alerts.json | jq

# 4) 학생이 attacker 에서 SQLi 발사 → 즉시 alert
docker exec 6v6-attacker bash -c "curl -s -A 'sqlmap/1.7' \
    \"http://web/?q=' UNION SELECT 1,2,3--\""
sleep 3
docker exec 6v6-siem grep -i sqli /var/ossec/logs/alerts/alerts.json | tail

# 5) Windows (옵션) Sysmon → SIEM 도달 확인
docker exec 6v6-siem grep -c "6v6-win" /var/ossec/logs/archives/archives.json
```

## Assessor — 읽기 전용 평가 수집 레이어 (CC/tubewar 채점)

중앙 플랫폼(CC)이 학생 VM에서 채점에 필요한 상황정보를 **읽기 전용 + API 키**로 당겨가는
별도 서비스. Bastion·토폴로지·Wazuh 코어와 완전히 별개다. CC 는 raw 명령이 아니라 선언적
*check-spec* 만 보내고, Assessor 가 **고정 명령 템플릿 + 화이트리스트**로만 안전 명령을 합성한다.

```bash
KEY=ccc-api-key-2026
# WAF 차단 모드 + Suricata 동작 + SQLi 탐지 알림을 한 번에 질의 (부작용 0)
curl -s -H "Host: assessor.6v6.lab" -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -X POST http://<VM_IP>/assess -d '{"checks":[
    {"id":"waf","type":"file_contains","target":"web","params":{"path":"/etc/modsecurity/modsecurity.conf","pattern":"SecRuleEngine On"}},
    {"id":"ips","type":"process_running","target":"ips","params":{"pattern":"suricata"}},
    {"id":"det","type":"wazuh_alert","params":{"groups":["web_attack"],"since_sec":3600}}]}'
```

- 컨테이너 `6v6-assessor` (dmz 10.20.32.55), `http://assessor.6v6.lab/health`.
- `bash 6v6.sh up` 이 기본 활성, `SKIP_ASSESSOR=1` 로 생략(base 컨테이너 무영향).
- 두 표면: **`/assess`**(채점 pass/fail) + **`/activity`**(실습 모니터링 피드 — 최근
  명령/FIM/알림/서비스 상태). 둘 다 read-only·`X-API-Key`.
- 채점용 정적 수집(cohort-free): FIM(syscheck) + 셸 명령 로깅을 모든 학생 동일하게 켠다 →
  `fim_change` / `command_ran` / `/activity` 질의 가능. **클라이언트엔 과목/학년/index 로직이 없다.**
- cross-infra 듀얼(VM↔VM 공격) 도달성 모델은 새 노출 없이 기존 외부 표면 그대로 사용.
- check type·`/activity` 계약·예시·cross-infra·보안 노트 전체: **[ASSESSOR.md](ASSESSOR.md)**.

## 명령어

```bash
bash 6v6.sh up                       # 13 컨테이너 빌드 + 기동
bash 6v6.sh up --with-windows        # 14 컨테이너 (+ Windows tiny11; KVM 사전검사)
bash 6v6.sh smoke                    # 외부 노출 포트 + Wazuh agent 등록 + 컨테이너 헬스
bash 6v6.sh status                   # 컨테이너 상태 + 접속 안내 (Windows 포함)
bash 6v6.sh logs <svc>               # 컨테이너 로그 follow
bash 6v6.sh down                     # 중단 (Windows 도 같이 down, 볼륨 보존)
bash 6v6.sh destroy                  # 컨테이너 + 볼륨 + 이미지 모두 삭제

# Windows 엔드포인트 후속 관리 (base 가동 후 별도 옵션)
bash 6v6.sh windows up               # Windows 만 시작 (KVM 사전검사)
bash 6v6.sh windows status           # 부팅 진행 / OEM 완료 여부
bash 6v6.sh windows down             # Windows 만 중단
bash 6v6.sh windows destroy          # Windows compose down -v (win-storage/ 는 별도 삭제 필요)
bash 6v6.sh windows logs             # 부팅·OEM 진행 로그
```

## 300B 와의 차이점

| 항목 | 300B | 6v6 |
|------|------|-----|
| 토폴로지 | 4-tier (edge/dmz/private/mgmt) | **4-tier** (ext/pipe/dmz/int) |
| 컨테이너 수 | 18 | 15 base (+1 Windows 옵션) |
| 외부 노출 포트 | 4 (80/443/53/2204) | 7 |
| 방화벽 / IPS / WAF | 통합 | **분리** — fw(nftables) / ips(Suricata) / web(ModSec) |
| Wazuh | 3 컨테이너 (manager+indexer+dashboard) | **3 컨테이너 동일** (manager+indexer+dashboard) |
| 취약 웹 | 7 (juice/dvwa/neobank/govportal/mediforum/admin/ai) | 7 (동일, int zone 격리) |
| Wazuh agent | 미포함 (300B 는 raw 로그 마운트) | ips+web (+옵션 win) 에 설치 |
| syslog forward | 미포함 | bastion+attacker → siem 514/udp |
| Windows 엔드포인트 | 미포함 | 옵션 `--with-windows` (tiny11 + Sysmon) |

## 트러블슈팅 — `X /dev/kvm missing` (Windows 옵션)

`bash 6v6.sh up --with-windows` 시 발생. 환경별 5단계 순서 (가장 흔한
**Windows 호스트 → VMware → Linux 게스트 → 6v6** 시나리오 기준):

```
1. Win 호스트 BIOS → Intel VT-x (or SVM) Enabled
2. Win 호스트 PowerShell(관리자):
     bcdedit /set hypervisorlaunchtype off
   + "Windows 기능": Hyper-V, Virtual Machine Platform, Windows Hypervisor Platform,
     WSL, Sandbox 모두 해제 → 재부팅
3. VMware Workstation: Linux VM 종료 → Settings → Processors
     → ✅ Virtualize Intel VT-x/EPT or AMD-V/RVI
4. Linux 게스트:
     sudo modprobe kvm_intel              # 또는 kvm_amd
     sudo usermod -aG kvm $USER && newgrp kvm
5. bash 6v6.sh up --with-windows          # 재시도
```

진단 한 줄 (Linux 게스트에서):
```bash
ls -l /dev/kvm; egrep -c '(vmx|svm)' /proc/cpuinfo; lsmod | grep kvm; systemd-detect-virt
```

상세 4 case 분기 + ESXi 안내는 [`WINDOWS-ENDPOINT.md`](./WINDOWS-ENDPOINT.md#트러블슈팅) 참조.
KVM 활성 불가하면 `--with-windows` 빼고 `bash 6v6.sh up` 만 — 본 스택 15컨테이너는
정상 동작 (Windows 관련 lab/lecture step 만 건너뜀).

## 라이선스

MIT — 자유롭게 학습/수업에서 활용.
