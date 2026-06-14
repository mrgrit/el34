# GovPortal — 25 취약점 카탈로그

> ⚠️ 강사·평가자 전용. 정부 민원 도메인 의도적 취약 시스템.

## 강조 영역
SAML/JWT 우회 · 파일 업로드 · 권한 상승 (authority_level) · CSRF · audit log tampering

## 매핑

| # | 코드 | OWASP | 카테고리 | 위치 | PoC |
|---|------|-------|----------|------|-----|
| 1 | V01 | A07 AuthFail | SAML signature 검증 약함 | `POST /saml/login` | `<Response><ssn>임의SSN</ssn></Response>` (서명 없이도 통과) |
| 2 | V02 | A07 AuthFail | SAML JIT auto-provisioning | 같은 endpoint | 임의 SSN 으로 자동 계정 생성 |
| 3 | V03 | A05 Misconfig | SAML issuer 무검증 | 같은 endpoint | 임의 IDP 응답 수용 |
| 4 | V04 | A03 Injection | SQLi — login form | `POST /login` | `ssn=' OR 1=1--&password=x` |
| 5 | V05 | A02 Crypto | JWT 약한 secret | hardcoded `gov-shared-secret-2023` | jwt.io brute-force |
| 6 | V06 | A02 Crypto | JWT 'none' 알고리즘 허용 | `current_user()` | `Authorization: Bearer eyJ.alg=none.` |
| 7 | V07 | A04 Insecure Design | 예측 가능 cert_number | 자동 발급 시 | `CERT-{year}-{citizen_id:04d}-{aid:03d}` 패턴 enumerate |
| 8 | V08 | A01 BAC | 권한 상승 — X-Authority-Level | `current_user()` | header `X-Authority-Level: 99` |
| 9 | V09 | A05 Misconfig | 파일 업로드 — 확장자/MIME 검증 0 | `POST /apply` (multipart) | `.php`/`.jsp`/`.exe` 업로드 |
| 10 | V10 | A08 Integrity | CSRF — apply form 토큰 부재 | `POST /apply` | 외부 사이트 form auto-submit |
| 11 | V11 | A03 Injection | Stored XSS — 신청서 content | `apply.html` → `dashboard.html` | `<script>alert(1)</script>` |
| 12 | V12 | A09 Logging | Audit log tampering — 본인 로그 삭제 | `POST /api/audit/clear?actor=` | `actor=admin` 전체 삭제 |
| 13 | V13 | A05 Misconfig | Path Traversal — uploaded filename | `POST /apply` filename | `f.filename = "../../../etc/passwd"` |
| 14 | V14 | A05 Misconfig | XXE — applications/import | `POST /api/applications/import` | `<!DOCTYPE [<!ENTITY x SYSTEM "file:///etc/passwd">]>` |
| 15 | V15 | A01 BAC | IDOR — 다른 사람 신청서 조회 | `GET /applications/<id>` | `/applications/3` (alice 의 것을 bob 이 조회) |
| 16 | V16 | A01 BAC | 강제 승인 — 권한 검증 0 | `POST /applications/<id>/approve` | 시민 권한으로 승인 → 본인 cert 발급 |
| 17 | V17 | A05 Misconfig | LFI/Path Traversal — cert download | `GET /cert/download?path=` | `path=/etc/passwd` |
| 18 | V18 | A02 Crypto/PII | PII bulk export — 보호 약함 | `GET /api/citizens/export.csv` | 시민 SSN/주소/전화 평문 CSV |
| 19 | V19 | A07 AuthFail | X-Forwarded-For trust 우회 | `GET /api/admin/citizens` | header `X-Forwarded-For: 127.0.0.1` |
| 20 | V20 | A01 BAC | Mass assignment — 프로필 수정 | `POST /api/profile/update` | `{"role":"admin","authority_level":99,"ssn":"..."}` |
| 21 | V21 | A07 AuthFail | Default admin PIN | `POST /admin/console` | `pin=1234` |
| 22 | V22 | A01 BAC | SSN 변경 가능 (V20 의 일부) | 같은 endpoint | 다른 시민 SSN 으로 합병 |
| 23 | V23 | A09 Logging | Verbose error — SQL stack | `POST /login` SQL 실패 | 스키마 leak |
| 24 | V24 | A06 Vuln Components | Banner — Apache 2.4.49 (CVE-2021-41773) | 모든 응답 `Server` 헤더 | path traversal CVE 표적 인식 |
| 25 | V25 | A05 Misconfig | 보안 헤더 부재 (CSP/X-Frame-Options/HSTS) | 모든 응답 | clickjacking + MitM 취약 |

## 권장 공방 시나리오 (Battle 기준)

| 단계 | 공격 (RED) | 방어 (BLUE) |
|------|-----------|-------------|
| 정찰 | `Server` banner + `/admin/console` PIN brute | banner 제거, PIN lockout |
| 인증 우회 | V01 SAML 서명 없이 ssn 임의 / V04 SQLi / V06 JWT none | XML signature 검증, parameterized SQL, JWT alg whitelist |
| 권한 상승 | V08 X-Authority-Level / V20 mass assign role | header trust 제거, role allowlist |
| 데이터 탈취 | V18 CSV export / V15 IDOR / V19 X-Forwarded-For | RBAC + 응답 필드 마스킹 |
| 파일 업로드 → RCE | V09 .php upload + V13 traversal → 웹쉘 | 확장자 whitelist + secure_filename + Content-Type 검증 |
| 흔적 삭제 | V12 audit log clear | append-only audit + immutable storage |

## 점수 가중

| 난이도 | claim 점수 | 사례 |
|--------|-----------|------|
| Trivial | +5 | V21 default PIN, V24 banner |
| Easy | +10 | V04 SQLi, V11 stored XSS, V25 보안 헤더 |
| Medium | +20 | V01 SAML 우회, V09 file upload, V12 audit tamper, V18 CSV export |
| Hard | +30 | V14 XXE, V20 mass assign role 상승, V09+V13 chain → webshell |
| Chain | +40 | V01 SAML 임의 SSN → V20 role=admin → V12 audit clear |

## 운영자 점검
- 실행: `python app.py` (port 3002)
- 시드 시민 5명 (admin/김철수/이영희/박민수/정수정)
- 권한 레벨: 1(citizen) / 5(clerk) / 7(officer) / 99(admin)
- DB 초기화: `neobank.db` 삭제 후 재실행
