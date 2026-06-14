# modsec_edu_gui — WAF(ModSecurity) 교육용 GUI

보안시스템을 처음 다루는 학생이 **WAF(ModSecurity)** 의 SecRule 작성을 장비형 웹 콘솔로 배우는
교육용 도구다. 6v6 secuops-easy 특강(W5 WAF 기초, W6 WAF 시나리오)에서 사용한다.

핵심 철학: 학생이 폼에서 탐지 조건을 구성하면 → **실제 SecRule 한 줄로 변환**해 미리보기 →
`/etc/modsecurity/edu_rules.conf` 에 적용 → `apache2ctl configtest` 통과 시에만 graceful reload.
**잘못된 룰은 configtest 에서 걸러져 Apache 를 죽이지 않는다**(실패 시 직전 상태 자동 복원).

## 특징
- **의존성 0** — Python 3 표준 라이브러리만. 6v6-web 컨테이너 안에서 root 로 실행.
- SecRule 구조 분석기 + CRS 패밀리 브라우저 · SecRule 빌더(변수/연산자/패턴/변환/액션) ·
  audit 로그 뷰어(차단/anomaly score/룰 ID) · SIEM(Wazuh) 연동 · 침해대응 훈련 30종.
- GUI 룰 id ≥ 9000000(CRS 900000-999999 와 분리), 삭제는 id 기준.
- 입력값 정규식 화이트리스트. 변수/연산자/변환/액션/severity 는 화이트리스트.

## 구성
```
server.py              # http.server 백엔드 + JSON API (configtest 보호 적용/복원)
static/index.html/app.js/style.css
static/scenarios.json  # SecRule 작성 시나리오 30
deploy.sh
```

## 실행 / 배포
```bash
python3 server.py 8080        # 로컬 테스트
./deploy.sh 6v6-web 8080      # 6v6 호스트에서 컨테이너로
```

## API 요약
| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/status | Apache/ModSec/CRS/엔진모드/audit 크기 |
| GET | /api/config | modsec 지시어 · CRS 패밀리 · 폼 옵션 |
| GET | /api/rules | edu_rules.conf 파싱 + next_id |
| GET | /api/crs_sample?prefix= | CRS 파일 SecRule 샘플 |
| GET | /api/audit?n=&blocked= | modsec_audit.log 파싱(uri/status/score/룰ID) |
| GET | /api/siem | Wazuh 연동 상태 |
| POST | /api/rule/analyze · /api/rule/preview · /api/rule/apply · /api/rule/delete | SecRule |
| POST | /api/siem/enable | audit.log → Wazuh |
| POST | /api/scenario/check | 시나리오 검증 |

## 안전장치
- apply: 새 룰을 쓰기 전 현재 edu_rules.conf 백업 → 쓰기 → `apache2ctl configtest`.
  Syntax OK 면 graceful, 아니면 **즉시 백업 복원** + 문법 오류 반환(운영 WAF 보호).
- SecRule action 은 deny(403 차단)/pass(탐지·로그)/drop/block 중 선택.

> 교육용 도구. 운영 WAF 에 그대로 쓰지 말 것.
