# el34 — 6v6 재설계 (출처 IP 보존 + 단순 네트워크)

원본 6v6 의 **NAT 출처추적 결함**(외부 공격자 IP가 HAProxy/masquerade 로 게이트웨이 IP에
덮여 SIEM·차단에서 식별 불가)을 근본 제거한 재설계.

## 핵심 변경 (vs 6v6)

| 항목 | 6v6 (이전) | el34 (현재) |
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

## 배포 절차 (.151)
```bash
# 0) 1회: daemon.json 에 {"userland-proxy": false} → systemctl restart docker
cd ~/el34
cp .env.example .env            # 값 채우기 (LLM_BASE_URL=외부 GPU)
docker compose build
docker compose up -d            # 코어
./el34-net.sh                   # ★ 호스트 글루 (bridge-nf-call=0 + DOCKER-USER) — 필수
# TI/EDR 오버레이:
docker compose -f docker-compose.yaml -f docker-compose.misp.yml \
  -f docker-compose.opencti.yml -f docker-compose.sysmon.yml \
  --env-file .env --env-file .env.misp --env-file .env.opencti up -d
cd sigma && ./install-sigma.sh  # Sigma 룰 적재
```

## 출처 IP 보존 — 검증 결과
공격자 → fw → ips → web 경로에서 **보안장비 전 계층이 진짜 출처 IP를 봄**:
- Suricata(IPS) eve.json: `src_ip: <attacker>`
- ModSecurity(WAF) audit: `remote_address: <attacker>`  ← 차단 기준이 진짜 공격자
- Apache access log: `<attacker>`

> 6v6 은 같은 지점에서 `10.20.32.1`(게이트웨이)로 덮였음 → el34 에서 해결.
