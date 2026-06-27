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

> 네트워크 전제: 호스트 IP 가 compose 와 일치해야 함 — 웹 `192.168.0.161`(ens37),
> 내부 GUI `192.168.136.145`(ens38). DHCP 가변이면 netplan static 권장(README/세션 참조).
> MISP/OpenCTI 는 `.136.145` 에 바인딩 → 호스트 Firefox 전용·LAN 격리.

## 출처 IP 보존 — 검증 결과
공격자 → fw → ips → web 경로에서 **보안장비 전 계층이 진짜 출처 IP를 봄**:
- Suricata(IPS) eve.json: `src_ip: <attacker>`
- ModSecurity(WAF) audit: `remote_address: <attacker>`  ← 차단 기준이 진짜 공격자
- Apache access log: `<attacker>`

> 이전 설계는 같은 지점에서 `10.20.32.1`(게이트웨이)로 덮였음 → el34 에서 해결.
