# el34 — 재설계 (출처 IP 보존 + 단순 네트워크)

이전 설계의 **NAT 출처추적 결함**(외부 공격자 IP가 HAProxy/masquerade 로 게이트웨이 IP에
덮여 SIEM·차단에서 식별 불가)을 근본 제거한 재설계.

## 핵심 변경 (vs 이전 설계)

| 항목 | 이전 설계 | el34 (현재) |
|---|---|---|
| 엣지 | HAProxy L7 종료 (출처 소실) | **제거** — fw 가 L3 포트분기 DNAT 만 |
| ips | dmz 로 masquerade (출처→게이트웨이) | **masquerade 제거** — 출처 native 보존 |
| 호스트 publish | docker-proxy (출처→게이트웨이) | **userland-proxy=false** — DNAT 가 출처 보존 |
| 리턴 경로 | masquerade 의존 | ips default GW=fw → conntrack 역추적 |
| 사이트 라우팅 | HAProxy Host 헤더 | **포트분기**(.161:8001-8007) + Host 헤더 병행 |
| 외부 공격자 | 컨테이너(wan, NAT 뒤) | **별도 VM 192.168.0.202** |
| Windows | dockurr/windows | 보류 (추후 독립 HW) |
| Sigma | 없음 | **신규 추가** (sigma/ → Wazuh 룰) |

## 토폴로지 (.151 = elf4, VMware, Ubuntu Desktop 23GB/8vCPU)

```
외부 공격자 VM (192.168.0.202)
        │  LAN 192.168.0.0/24
        ▼
  ens37 = 192.168.0.161  (웹/dmz 외부 진입; .161:80/443/8001-8007 publish)
        │  userland-proxy=false → DNAT (출처 .202 보존)
   [el34-fw]  nftables 포트분기 DNAT (ext 10.20.30.1 / pipe 10.20.31.1)
        │  no masquerade
   [el34-ips] Suricata 인라인 IPS (pipe 10.20.31.2 / dmz 10.20.32.1), default GW=fw
        │
   [el34-web] Apache + ModSecurity + OWASP CRS = WAF (dmz 10.20.32.80 / int 10.20.40.80)
        │  ← 여기서 종료. remote_address = 192.168.0.202 (진짜 공격자!)
        ▼
   취약앱 7종 (int 10.20.40.81-87): juice/dvwa/neobank/govportal/mediforum/admin/ai

패킷 흐름(불변):  fw → ips → waf(web/ModSec) → app
```

### 내부 전용 (호스트 .151 Firefox 에서만, LAN 격리)
ens38 = 192.168.136.145 에 publish:
- SIEM 대시보드 `:5601`,  관리 포털 `:8000`
- 보안 콘솔 GUI: fw `:8081`, ips `:8082`, waf `:8083`
- MISP / OpenCTI (TI 플랫폼)

## 배포 절차 (.151) — 갓 설치한 Ubuntu 에서 한 방
```bash
git clone https://github.com/mrgrit/el34.git && cd el34
sudo ./el34.sh install     # Docker + daemon.json(userland-proxy=false)  ※ 그룹반영 위해 새 셸
./el34.sh up               # 인증서 생성 → env 생성 → build → core+overlay up → net glue → systemd → sigma
```
`el34.sh up` 이 자동 수행: Wazuh 인증서 생성(단일 CA 통일), `.env/.env.misp/.env.opencti` 생성,
코어 build+up, **오버레이 opencti→misp 순서**(redis=valkey 충돌 방지), `el34-net.sh`+systemd 설치,
Sigma 적재. (개별: `./el34.sh {install|up|down [-v]|net|certs|env|sigma}`)

> 네트워크 전제:
> - **웹 진입(`${WEB_HOST_IP}`)** — 최초 `el34.sh install` 이 **웹 진입 고정 IP 를 1회 질의**
>   (기본값=자동감지 VM IP)하여 ① `.env`(WEB_HOST_IP)에 고정하고 ② 그 IP 를 **유선 IF 에
>   netplan static 으로 고정**(확인 후 적용, cloud-init 네트워크 비활성). compose publish 는
>   `${WEB_HOST_IP}` 로 바인딩. 그래서 강의실 **DHCP 브리지 VM** 에서도 IP 가 재부팅에 불변이고
>   학생 hosts(`el34.lab → 이 IP`)와 바인딩이 일치해 **VM 밖에서 바로 접속**된다.
>   · 이후 `up`/재부팅은 `.env` 고정값 그대로 사용(재질문 없음).
>   · IP 변경: `WEB_HOST_IP_FORCE=1 ./el34.sh install`. static 롤백: `99-el34-static.yaml` 삭제 후 `netplan apply`.
>   · `0.0.0.0` 선택 시 모든 인터페이스 바인딩(static 생략, VM 실제 IP 로 접속). 무선 IF 는 static 자동 skip.
>   · 레거시 2-NIC(.151)는 `WEB_HOST_IP=192.168.0.161 ./el34.sh install` 로 명시 — 그대로 존중.
> - **내부 GUI `192.168.136.145`(ens38/dummy)** — MISP/OpenCTI/SIEM 대시보드 바인딩,
>   호스트 Firefox 전용·LAN 격리(변동 없음).

## 출처 IP 보존 — 검증 결과
공격자 → fw → ips → web 경로에서 **보안장비 전 계층이 진짜 출처 IP를 봄**:
- Suricata(IPS) eve.json: `src_ip: <attacker>`
- ModSecurity(WAF) audit: `remote_address: <attacker>`  ← 차단 기준이 진짜 공격자
- Apache access log: `<attacker>`

> 이전 설계는 같은 지점에서 `10.20.32.1`(게이트웨이)로 덮였음 → el34 에서 해결.
