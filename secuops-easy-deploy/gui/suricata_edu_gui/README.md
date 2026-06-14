# suricata_edu_gui — IPS(Suricata) 교육용 GUI

보안시스템을 처음 다루는 학생이 **IPS(Suricata)** 의 탐지룰 작성을 장비형 웹 콘솔로 배우는
교육용 도구다. 6v6 secuops-easy 특강(W3 IPS 기초, W4 IPS 시나리오)에서 사용한다.

핵심 철학: 학생이 폼에서 탐지 조건을 구성하면 → **실제 Suricata rule 한 줄로 변환**해 미리보기 →
local.rules 에 적용 → `suricatasc -c reload-rules` 로 라이브 반영 → **로딩 성공/실패를 즉시 표시**.
잘못 쓴 룰은 failed 카운트가 올라가므로 학생이 바로 피드백을 받는다.

## 특징
- **의존성 0** — Python 3 표준 라이브러리만. 6v6-ips 컨테이너 안에서 root 로 실행.
- 룰 구조 분석기(헤더+옵션 분해) · 룰 빌더(폼→미리보기→적용) · eve.json 뷰어(event_type 필터) ·
  SIEM(Wazuh) 연동 · 침해대응 훈련 30종(탐지룰 작성).
- GUI 룰은 sid ≥ 9000000 자동 배정(사전 시드 룰과 분리), 삭제는 sid 기준.
- 입력값 정규식 화이트리스트 검증. eve.json(수 GB)은 끝에서부터 N 줄만 읽음.

## 구성
```
server.py              # http.server 백엔드 + JSON API
static/index.html/app.js/style.css
static/scenarios.json  # 탐지룰 작성 시나리오 30
deploy.sh
```

## 실행 / 배포
```bash
python3 server.py 8080            # 로컬 테스트
./deploy.sh 6v6-ips 8080          # 6v6 호스트에서 컨테이너로
```

## API 요약
| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/status | 버전/가동/로딩룰수·실패/eve 크기 |
| GET | /api/config | HOME_NET·경로·디렉토리 |
| GET | /api/rules | local.rules 파싱 + ruleset-stats |
| GET | /api/eve?type= | eve.json tail (event_type 필터) + 분포 |
| GET | /api/fastlog | fast.log tail |
| GET | /api/siem | Wazuh 연동 상태 |
| POST | /api/rule/analyze | 룰 구조 분해 |
| POST | /api/rule/preview · /api/rule/apply · /api/rule/delete | 룰 빌더/적용/삭제 |
| POST | /api/siem/enable | eve.json → Wazuh 연동 |
| POST | /api/scenario/check | 시나리오 검증 |

## 메모
- Suricata 는 af-packet IDS 모드라 `drop` 은 실제 차단이 아닌 표식(IPS 모드/NFQ 필요).
- 기존 `local.rules` 가 `!src_ip` 같은 잘못된 옵션 문법이면 전부 로딩 실패하므로,
  본 도구는 올바른 문법(소스 제한은 헤더 `$EXTERNAL_NET`, 버퍼는 sticky buffer)으로 룰을 생성한다.

> 교육용 도구. 운영 IPS 에 그대로 쓰지 말 것.
