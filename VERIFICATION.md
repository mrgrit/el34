# el34 검증 리포트 (.151 배포 실측)

검증일: 2026-06-15 / 대상: 192.168.0.151 (elf4, VMware Ubuntu Desktop, 23GB/8vCPU)

## ✅ 핵심 목표 — 출처 IP 보존 (6v6 결함 제거)

6v6 은 HAProxy + ips masquerade 로 공격자 IP가 게이트웨이(10.20.32.1)로 덮여 식별 불가였음.
el34 은 **보안장비 전 계층이 진짜 출처 IP를 봄** — 두 경로 모두 실측 확인:

| 경로 | 출처 | 결과 |
|---|---|---|
| **외부 LAN → .161** (host publish, 실제 진입경로) | 192.168.0.79 | web/Apache 로그 `192.168.0.79` (포트분기 :8001 + Host헤더 :80) ✅ |
| **내부 체인** attacker→fw→ips→web | 10.20.30.202 | Suricata `src_ip` + ModSec `remote_address` + Apache + **SIEM 인덱스 `data.src_ip`** 전부 10.20.30.202 ✅ |

→ 외부 공격자 IP로 SIEM 식별·차단 가능. **결함 해결 입증.**

## ✅ 패킷 흐름 / 네트워크
- `fw → ips → waf(web/ModSec) → app` 강제 — 포트분기·Host헤더 양쪽 HTTP 200
- HAProxy 제거(L3 DNAT만), ips masquerade 제거, `userland-proxy=false`
- 호스트 글루: `bridge-nf-call-iptables=0` + DOCKER-USER inter-bridge ACCEPT (`el34-net.sh`)

## ✅ 컨테이너 (41 running / unhealthy 0 / restarting 0 / exited 0)
- 코어 16: fw, ips, web, 취약앱 7, wazuh(indexer/manager/dashboard), bastion, portal, attacker
- TI: MISP(core/modules/db/redis(valkey)/mail), OpenCTI(platform/worker×3/connector×10/elasticsearch/minio/rabbitmq/minio)
- EDR: Sysmon-for-Linux (BTF 존재 → 정상)

## ✅ SIEM
- 에이전트 등록: web, ips (Active)
- Suricata(eve.json) + ModSec(modsec_audit.log) 수집 → manager → indexer 색인
- 공격 알림에 `data.src_ip=10.20.30.202` 색인 확인

## ✅ 내부 전용 GUI (.136.145 = ens38 NAT, 호스트 Firefox 전용, LAN 격리)
| 서비스 | URL | 결과 |
|---|---|---|
| SIEM 대시보드 | https://192.168.136.145:5601 | 302 ✅ |
| 관리 포털 | http://192.168.136.145:8000 | 200 ✅ |
| fw 콘솔(nftables) | http://192.168.136.145:8081 | 200 ✅ |
| ips 콘솔(Suricata) | http://192.168.136.145:8082 | 200 ✅ |
| waf 콘솔(ModSec) | http://192.168.136.145:8083 | 200 ✅ |
| MISP | https://192.168.136.145:8443 | 302 ✅ |
| OpenCTI | http://192.168.136.145:8080 | 200 ✅ |

LAN 격리 확인: 위 서비스 모두 외부면 .161 에서 접근 시 000(거부) ✅

## ✅ Sigma → Wazuh (신규)
- `sigma/` 3룰 → Wazuh 룰(id 200001+) 변환·적재, manager reload 정상
- `wazuh-logtest` 로 rule 200001(SSH brute) 발화 확인

## ⚠ 스킵 / 인프라 이슈 (사유 명시)

1. ~~외부 공격자 VM .202 DOWN~~ → **[해결·검증완료 2026-06-15]** .202 전원 인가 후 실측:
   `.202 → .161 → fw → ips → waf → app` 에서 **WAF/Apache 로그·ModSec `remote_address`·Suricata
   `src_ip`·SIEM `data.src_ip` 전부 `192.168.0.202` 보존**. SIEM 에 Suricata 탐지 93건
   (SQLi UNION SELECT, sqlmap UA, XSS, Path Traversal)이 `data.src_ip:192.168.0.202` 로 귀속.
   dvwa SQLi 는 ModSec 가 403 차단. → 외부 공격자 IP 식별·차단 완전 동작.
2. **tubewar(.107) 콘텐츠 기반 검증 미수행** — .107 은 SSH(:22)만 열림, 자격증명/API 없음(별도 플랫폼).
   시나리오·미션 콘텐츠로의 검증은 tubewar 접근 권한 확보 후 진행 필요.
3. **MISP healthcheck 간헐 unhealthy** — 헬스체크 timeout 1s 가 과도(서비스는 301/302 정상 응답, 원본 6v6도 동일). 기능 무관·표시상 이슈. (현재는 healthy)
4. **WAF/Apache 알림의 SIEM `data.srcip` 미색인** — 외부 공격자 IP 추적은 Suricata(`data.src_ip`)
   경로로 완결(93건 귀속). ModSec/Apache 쪽은 파일 레벨엔 `remote_address`로 출처가 보존되나
   Wazuh 알림 `data.srcip` 로는 색인되지 않음(web access-log 디코더/localfile 튜닝 시 해결).
   핵심(외부 IP 식별·차단)엔 영향 없음.

## ✅ Fresh 배포 검증 (2026-06-19, .151 완전 teardown 후 github clone → el34.sh)
빈 상태(컨테이너/이미지/certs/.env 0)에서 **`git clone` → `sudo ./el34.sh install` → `./el34.sh up`** 만으로:
- Wazuh 인증서 자동 생성(단일 CA 통일, verify OK) + `.env/.env.misp/.env.opencti` 자동 생성
- 코어 build/up + 오버레이(opencti→misp) + el34-net + systemd + Sigma → **41 컨테이너 / unhealthy 0**
- 출처 IP 보존 재확인: `.202 → .161` 공격이 web 로그 `192.168.0.202`, dvwa SQLi **ModSec 403 차단**,
  SIEM `data.src_ip:192.168.0.202` 색인.
- 이 과정에서 발견·수정한 갭: (1) 인증서 생성기가 파일을 root/0400 으로 잠금 → up 을 root 로 실행 +
  인증서 ccc:644 정규화, (2) MISP db 첫부팅 레이스 → overlay up 3회 재시도.

## ⚠ 운영 주의 (중요)
- **`el34-net.sh` 는 `docker compose up`/컨테이너 재생성 때마다 재실행**해야 함.
  Docker 가 컨테이너 재생성 시 iptables 를 재작성하며 DOCKER-USER inter-bridge ACCEPT 룰을 흩뜨림
  → 미실행 시 fw→ips→web 체인 및 외부 .161 진입이 끊김. (bridge-nf-call=0 은 sysctl.conf 영속,
  DOCKER-USER 룰은 런타임 → systemd unit/post-up hook 으로 자동화 권장.)
