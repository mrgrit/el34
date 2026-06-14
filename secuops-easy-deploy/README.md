# secuops-easy 특강 배포 (방화벽·IPS·WAF 교육용 GUI)

보안시스템 입문 특강(secuops-easy, 6주)에서 쓰는 세 개의 장비형 교육용 GUI 를 6v6 인프라에
배포·검증하는 번들이다. 학생은 모든 조작을 웹 콘솔로 하고, GUI 가 만들어내는 실제 명령
(`nft` / Suricata rule / SecRule)을 함께 배운다.

## 구성 요소

| 장비 | GUI 레포 | 배포 대상 | 학생 접속 |
|------|----------|-----------|-----------|
| 방화벽(nftables) | `mrgrit/nft_edu_gui` | 6v6-fw :8080 | http://fw-gui.6v6.lab |
| IPS(Suricata) | `mrgrit/suricata_edu_gui` | 6v6-ips :8080 | http://ips-gui.6v6.lab |
| WAF(ModSecurity) | `mrgrit/modsec_edu_gui` | 6v6-web :8080 | http://waf-gui.6v6.lab |

각 GUI 는 **Python 표준 라이브러리만** 사용(pip 불필요), 단일 `server.py` + 정적 파일로
컨테이너 안에서 root 로 동작한다.

> **2026-06 구조 변경 (배포 신뢰성).** 세 GUI 소스는 이제 이 번들의 `gui/` 에 **vendoring**되어
> fw/ips/web **이미지에 COPY**되고, 각 컨테이너 entrypoint 가 :8080 으로 **자동 기동**한다.
> HAProxy vhost 라우트도 `fw/haproxy.cfg`(base)에 포함된다. 따라서 `down→up`·재부팅 후
> **GitHub clone 도, 런타임 HAProxy 패치도 없이** 세 콘솔이 즉시 열린다. `deploy_all.sh` 는
> 이제 그 상태를 검증/치유하는 **오프라인** 보조 도구일 뿐이다(아래 "사용법").

## 이 번들이 적용하는 인프라 보정

배포 과정에서 다음 보정을 함께 적용한다(2026-05-27 6v6 실측 기준 필요했던 수정).

| 파일 | 무엇을 고치나 | 왜 |
|------|--------------|----|
| `fix_modsec.py` | `/etc/modsecurity/modsecurity.conf` 의 중복·잘린 예외 블록(`SecRule REMOTE_ADDR @ipMatch` 등) 정규화 | 문법 오류로 Apache 가 기동 실패(AH00526)하던 것 복구 |
| `suricata_local.rules.baseline` | `/etc/suricata/rules/local.rules` 를 올바른 문법으로 교체 | 기존 `!src_ip` 잘못된 옵션으로 전 룰 로딩 실패(rules_loaded 0)하던 것 복구 → 5/0 |
| `patch_haproxy.py` | (구 이미지 backward-compat) `fw/haproxy.cfg` 에 GUI 라우트가 **없을 때만** 주입 | 현재는 base config 에 내장 → 보통 no-op |

> **과거 사고 기록.** 매 배포마다 `patch_haproxy.py` 로 HAProxy config 를 패치 후 reload 했는데,
> 앵커 공백 불일치(`is_bastion ` 1칸 vs base 2칸)로 패치가 **영구 실패** → GUI 라우트가 안 들어가
> 세 콘솔이 `default_backend`(웹 랜딩)로 **fallthrough**(거짓 200)하던 버그가 있었다. 또 reload 후
> 구 프로세스 정리 레이스로 404 가 나기도 했다. 2026-06 부터 라우트를 base config 에 직접 두어
> 이 패치/reload 경로 자체를 제거했다.

## 사용법

보통은 **아무것도 할 필요 없다** — `bash 6v6.sh up` 이 이미지 빌드 시 GUI 를 내장하고,
컨테이너 entrypoint 가 자동 기동한다. 콘솔이 안 열리는 것 같을 때만 아래 **오프라인 검증/치유**를
돌린다(네트워크 불필요, 멱등):

```bash
bash secuops-easy-deploy/deploy_all.sh
```

GUI 소스(`gui/<repo>/`)를 수정했다면 이미지를 다시 빌드해야 반영된다:
```bash
docker compose -f docker-compose.yaml --env-file .env build fw ips web && \
docker compose -f docker-compose.yaml --env-file .env up -d fw ips web
```

> vendored 소스를 upstream(`mrgrit/*_edu_gui`)에서 갱신하려면 각 레포의 `server.py` + `static/` 을
> `gui/<repo>/` 에 덮어쓰고 위 빌드를 다시 한다.

## 검증(스모크)

```bash
bash 6v6.sh smoke   # "교육용 콘솔" 섹션이 세 콘솔의 실제 title 을 확인 (랜딩 fallthrough 거짓 200 차단)

# 수동 확인 — 200 만 보면 안 되고 title 에 '콘솔' 이 있어야 진짜 콘솔이다:
for g in fw ips waf; do
  curl -s -H "Host: $g-gui.6v6.lab" http://<VM_IP>/ | grep -o '<title>[^<]*</title>'
done
docker exec 6v6-ips suricatasc -c ruleset-stats   # rules_loaded>=5, failed 0
docker exec 6v6-web apache2ctl configtest          # Syntax OK
```

## SIEM(Wazuh) 연동
- 방화벽: GUI "SIEM 연동 켜기" → `/var/log/nft_edu/events.log` 를 Wazuh 에이전트가 tail.
- IPS: `/var/log/suricata/eve.json` (대개 기연동).
- WAF: `/var/log/apache2/modsec_audit.log` (대개 기연동).
- 매니저: 10.20.32.100.

## 강의 콘텐츠
교안/실습(6주)은 CCC 레포 `contents/standalone/{lecture,lab}/secuops-easy/` 에 있으며 6v6 Training
UI(`/api/standalone/secuops-easy/...`)로 서빙된다.

> 교육용 도구. 운영 보안장비에 그대로 쓰지 말 것.
