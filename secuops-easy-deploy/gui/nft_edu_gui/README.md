# nft_edu_gui — 방화벽(nftables) 교육용 GUI

보안시스템을 처음 다루는 학생이 **방화벽(nftables)** 을 장비형 웹 콘솔로 배우도록 만든
교육용 도구다. el34 secuops-easy 특강(W2 방화벽)에서 사용한다.

핵심 철학: 학생이 GUI 폼에서 룰/NAT 을 구성하면 → **그것이 만들어내는 실제 `nft` 명령을
미리보기로 보여주고** → 적용한다. "버튼"이 아니라 "명령"을 배운다.

## 특징
- **의존성 0** — Python 3 표준 라이브러리만 사용 (폐쇄망 컨테이너에 그대로 투입).
- el34-fw 컨테이너 안에서 root 로 실행되며 실제 nftables 를 조작한다.
- 변경은 `inet six_filter` / `ip six_nat` 두 table 에만 허용 (Docker 의 `ip nat` 는 보호).
- 입력값은 정규식 화이트리스트로 검증 (명령 인젝션 차단).
- 기능: 대시보드 · 인터페이스/존 · 룰 관리(미리보기→적용→삭제) · NAT(DNAT/SNAT) ·
  Stateful(conntrack) · 로그·활동(카운터+이벤트) · SIEM(Wazuh) 연동 · 침해대응 훈련 10종.

## 구성
```
server.py            # http.server 백엔드 + JSON API + 정적 서빙
static/index.html    # 장비형 UI
static/app.js        # vanilla JS
static/style.css     # 다크 appliance 테마
static/scenarios.json# 침해대응 훈련 시나리오 10
deploy.sh            # 컨테이너 배포
```

## 실행 / 배포
```bash
# 로컬 단독 실행 (테스트):  python3 server.py 8080
# el34 호스트에서 컨테이너로 배포:
./deploy.sh el34-fw 8080

# 원격(예: 작업 PC)에서 ssh 경유 배포:
HOST=192.168.0.105
sshpass -p '1' scp -r . ccc@$HOST:/tmp/nft_edu_gui
sshpass -p '1' ssh ccc@$HOST 'cd /tmp/nft_edu_gui && bash deploy.sh el34-fw 8080'
```

## API 요약
| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET | /api/status | 호스트/버전/인터페이스/룰수/연결수 |
| GET | /api/ruleset | 파싱된 룰셋 + raw |
| GET | /api/conntrack | 연결 추적 테이블 |
| GET | /api/events | 이벤트 로그 tail |
| GET | /api/siem | Wazuh 연동 상태 |
| GET | /api/scenarios | 훈련 시나리오 |
| POST | /api/rule/preview · /api/rule/apply · /api/rule/delete | 필터 룰 |
| POST | /api/nat/preview · /api/nat/apply | NAT 룰 |
| POST | /api/counters/reset | 카운터 리셋 |
| POST | /api/siem/enable · /api/siem/disable | Wazuh 연동 토글 |
| POST | /api/scenario/check | 시나리오 검증 |

## 안전장치
- apply 는 `nft add/insert rule {inet six_filter | ip six_nat} …` 형태만 허용.
- 주소/포트/rate/식별자는 정규식 화이트리스트 통과 후에만 명령에 삽입.
- 삭제는 handle 기반, 허용 table 한정.

> 교육용 도구. 운영 방화벽에 그대로 쓰지 말 것.
