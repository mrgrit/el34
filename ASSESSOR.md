# 6v6 Assessor — 읽기 전용 평가 수집 레이어

중앙 플랫폼(CC/tubewar)이 학생별 6v6 VM에서 **채점·모니터링에 필요한 상황정보를
읽기 전용으로 당겨갈 수 있도록** 추가된 별도 서비스다. Bastion·토폴로지·취약웹·Wazuh
코어는 일절 손대지 않는다.

> **클라이언트는 문맥 없이(dumb) 수집만 한다.** 과목/학년/반/팀(Cohort)·index 분리
> 로직은 6v6 안에 없다 — 그건 전적으로 서버(tubewar)의 책임이다. 같은 6v6 이미지가
> 여러 과목·학년에 재사용되므로, 어떤 수업인지 클라이언트는 알지 못한다.

---

## 1. 구성

| 항목 | 값 |
|------|----|
| 컨테이너 | `6v6-assessor` (dmz, `10.20.32.55`) |
| 스택 | `python:3.12-slim` + FastAPI + docker SDK + httpx |
| 외부 노출 | `http://assessor.6v6.lab/` (fw HAProxy, WAF 우회 — portal 과 동일) |
| 인증 | `X-API-Key` (env `API_KEY`, 기본 `ccc-api-key-2026`) |
| 마운트(전부 read-only) | `/var/run/docker.sock`, `wazuh-manager-logs`, `ips-suricata-logs`, `web-apache-logs` |
| 토글 | `SKIP_ASSESSOR=1 bash 6v6.sh up` → 생성 안 함(base 무영향) |
| (옵션) provisioner | `6v6-provisioner` (dmz `10.20.32.56`) — write 서비스, **기본 OFF**(`SKIP_PROVISIONER=0` 으로만 기동). §10 |

Assessor 는 compose profile `assessor` 로 묶여 있어 `bash 6v6.sh up` 이 기본 활성화하고,
`SKIP_ASSESSOR=1` 이면 profile 미활성 → 컨테이너 자체가 생성되지 않는다. (옵션 provisioner 는
profile `provisioner` 로 분리되어 기본 미생성.)

---

## 2. 동작 원리 — 게이트키퍼

CC 는 **절대 raw 명령을 보내지 않는다.** 선언적 *check-spec* 만 보내고, Assessor 가
이를 **고정 명령 템플릿 + 파라미터 화이트리스트**로만 안전 명령으로 변환해 실행한다.

```
CC ──(check-spec, X-API-Key)──▶ Assessor ──┬─ 호스트 상태: docker.sock 로 read-only exec
                                            │   (stat/grep/sha256sum/pgrep/ss/tail — argv 직접)
                                            └─ 보안 알림: 로컬 Wazuh alerts.json 질의(+옵션 indexer)
        ◀──(pass/fail + evidence)──────────┘
```

- **모든 검사 부작용 0.** 쓰기·변경·네트워크 공격 명령은 존재하지 않는다.
- **명령 주입 불가.** docker exec 는 셸 없이 argv 리스트를 직접 실행하며, path/pattern/port 는
  엄격한 화이트리스트(절대경로 + `[A-Za-z0-9._-/]`, `..` 금지, 제어문자 금지, 포트 1–65535)를
  통과해야 한다. 미지원 type·위험 파라미터는 `passed:false` 가 아니라 **명시적 `error` 로 거부**.

---

## 3. API — 두 표면

CC 는 두 가지 읽기 전용 표면을 당겨간다(둘 다 `X-API-Key`):
- **`POST /assess`** — 채점용. 선언적 check-spec → pass/fail + 근거.
- **`POST /activity`** — 실습 모니터링용. 학생의 최근 활동(명령/파일변경/알림/서비스) 스트림.

### `GET /health` (인증 불필요)
```json
{ "status": "ok", "service": "6v6-assessor",
  "hostname": "assessor", "version": "1.1.0", "wazuh_reachable": true,
  "surfaces": ["/assess", "/activity"],
  "supported_types": ["command_ran", "..."], "targets": ["attacker","bastion","..."],
  "alerts_source": "/data/wazuh/alerts/alerts.json", "indexer_enabled": false }
```

### `POST /assess` (헤더 `X-API-Key`)
요청:
```json
{
  "battle_id": "optional",
  "checks": [
    { "id": "c1", "type": "file_contains", "target": "web",
      "params": { "path": "/etc/modsecurity/modsecurity.conf", "pattern": "SecRuleEngine On" } }
  ]
}
```
응답:
```json
{
  "collected_at": "2026-06-03T12:00:00+00:00",
  "battle_id": "optional",
  "results": [
    { "id": "c1", "passed": true, "evidence": "12:SecRuleEngine On", "raw": { "exit_code": 0, "container": "6v6-web" } }
  ]
}
```
- `passed`: `true`/`false` = 검사 수행 결과. `null` + `error` = 수행 불가(미지원/위험/잘못된 파라미터).
- `evidence`: 근거 문자열(≤2KB).
- `raw`: 부가 메타(exit_code, container, matches 등).

### `POST /activity` (헤더 `X-API-Key`) — 실습 모니터링 피드
check-spec 가 채점용 pass/fail 이라면, `/activity` 는 **진도·병목 모니터링용 활동
스트림**이다. 신호원은 전부 그 VM 의 로컬 Wazuh. **raw 활동만 반환** — 진도/병목 판정·
Cohort 태깅은 tubewar 가 한다.

요청:
```json
{ "since_sec": 300, "limit": 200,
  "want": ["commands","fim","alerts","services"],
  "filter": { "container": "attacker", "user": "ccc", "groups": "syscheck" } }
```
- `want` 생략 시 4종 전부. `filter` 의 각 키는 선택(있으면 해당 항목만).
- `since_sec`/`limit` 로 범위 제한(큰 페이로드 방지, limit ≤ 1000).

응답:
```json
{ "collected_at": "iso8601",
  "commands": [ {"ts","container","user","cmd","exit","source"} ],   // source: prompt|auditd
  "fim":      [ {"ts","container","path","action","who"} ],          // action: added|modified|deleted
  "alerts":   [ {"ts","rule_id","level","description","agent","groups"} ],
  "services": { "apache":"up", "suricata":"up", "haproxy":"up", "recent_apache_errors": 0 } }
```
- `commands` ← 명령 로그(7절). `alerts` ← Suricata/ModSec/Sysmon 등 보안 알림(명령·FIM 은 별도 카테고리라 제외).
- 전부 read-only · Wazuh 기반(alerts.json 또는 indexer). **Cohort/과목/학년 개념 없음.**

---

## 4. target/container 별칭

`target` 또는 `container` 에 아래 표준 별칭(또는 `6v6-` 컨테이너명)을 쓴다. 어느 컨테이너에
exec 할지는 Assessor 내부 맵이 결정한다 — **클라이언트는 토폴로지를 몰라도 된다.**

| 별칭 | 컨테이너 | 비고 |
|------|----------|------|
| `fw` (=`firewall`,`secu`) | 6v6-fw | nftables + HAProxy |
| `ips` (=`ids`,`suricata`) | 6v6-ips | Suricata |
| `web` (=`waf`,`apache`) | 6v6-web | Apache + ModSecurity |
| `siem` (=`wazuh`,`manager`) | 6v6-siem | Wazuh manager |
| `attacker` | 6v6-attacker | |
| `bastion` | 6v6-bastion | |
| `juiceshop`(=`juice`) `dvwa` `neobank` `govportal` `mediforum` `adminconsole`(=`admin`) `aicompanion`(=`ai`) | 취약웹 7종 | |

---

## 5. check type 레퍼런스 (전부 읽기 전용)

### 호스트 상태 — osquery 우선 + docker.sock exec
상태 단언(파일/프로세스/포트)은 **osquery SQL**(read-only, 가장 안전)을 우선 사용하고,
osquery 가 없거나(attacker/취약웹) 안 되는 것(grep·해시·로그·nft 등)은 docker.sock 로
고정 argv 만 exec 한다. 응답 `raw.engine` 에 `osquery|exec` 표기.

| type | params | passed 조건 | 엔진(우선 → 폴백) |
|------|--------|-------------|------------------|
| `file_exists` | `path`, `target/container` | 파일 존재 | osquery `file` → `stat` |
| `file_contains` | `path`, `pattern`\|`regex`, `target` | 매치 1건+ | exec `grep -F\|-E -n -m1` |
| `file_hash` | `path`, `target`, `sha256?` | 해시 산출(또는 expected 일치) | exec `sha256sum` |
| `process_running` | `name`\|`pattern`, `target` | 프로세스 존재 | osquery `processes` → `pgrep -a -f` |
| `port_listening` | `port`, `target` | LISTEN 소켓 존재 | osquery `listening_ports` → `ss -ltn` |
| `log_contains` | `log`, `pattern`, `since_sec?`, `container?` | 매치 라인 존재 | exec `tail -n 4000` (파이썬 필터) |

> osquery SQL 은 파라미터를 SQL 리터럴로 안전 삽입(작은따옴표 이스케이프)하며 read-only(SELECT)
> 라 주입해도 write 불가. `process_running` 은 osqueryi 자기 프로세스를 제외(`name != 'osqueryi'`)해
> self-match false positive 를 막는다.

`log` 별칭: `suricata`(ips:/var/log/suricata/eve.json), `modsec`(web:/var/log/apache2/modsec_audit.log),
`apache_error`(web:/var/log/apache2/error.log), `auth`(container 의 /var/log/auth.log).

### 보안 알림/로그 — Wazuh 질의 (로컬 alerts.json, 옵션 indexer)
| type | params | passed 조건 |
|------|--------|-------------|
| `wazuh_alert` | `rule_id`\|`sid`\|`groups`\|`agent`, `since_sec?` | 조건 매칭 알림 존재 |
| `fim_change` | `path`\|`dir`, `since_sec?` | 해당 경로의 syscheck(FIM) 변경 알림 존재 |
| `command_ran` | `pattern`, `user?`, `since_sec?` | 패턴에 맞는 셸 명령 로그 존재 |

> 풍부 경로: `ASSESSOR_USE_INDEXER=1`(compose env) 로 Wazuh indexer(`https://10.20.32.110:9200`,
> admin/SecretPassword, self-signed→verify off) 병행 질의. 기본은 alerts.json(견고·무의존).

---

## 6. 예시

```bash
KEY=ccc-api-key-2026
ASSESS="curl -s -H Host:assessor.6v6.lab -H X-API-Key:$KEY -H Content-Type:application/json -X POST http://<VM_IP>/assess -d"

# 1) WAF 차단 모드 확인
$ASSESS '{"checks":[{"id":"waf-on","type":"file_contains","target":"web",
  "params":{"path":"/etc/modsecurity/modsecurity.conf","pattern":"SecRuleEngine On"}}]}'

# 2) Suricata 동작 + 80 리슨
$ASSESS '{"checks":[
  {"id":"suri","type":"process_running","target":"ips","params":{"pattern":"suricata"}},
  {"id":"p80","type":"port_listening","target":"web","params":{"port":80}}]}'

# 3) SQLi 탐지 알림 + 방화벽 룰 변경(FIM) + 위험 명령 실행
$ASSESS '{"checks":[
  {"id":"sqli","type":"wazuh_alert","params":{"groups":["web_attack"],"since_sec":3600}},
  {"id":"fw-fim","type":"fim_change","params":{"path":"/etc/nftables.conf","since_sec":3600}},
  {"id":"ran","type":"command_ran","params":{"pattern":"sqlmap","since_sec":3600}}]}'

# 4) 실습 모니터링 — 최근 5분 활동(명령/FIM/알림/서비스)
ACT="curl -s -H Host:assessor.6v6.lab -H X-API-Key:$KEY -H Content-Type:application/json -X POST http://<VM_IP>/activity -d"
$ACT '{"since_sec":300,"limit":100,"want":["commands","fim","alerts","services"]}'

# 5) attacker 의 명령만 필터
$ACT '{"since_sec":600,"want":["commands"],"filter":{"container":"attacker"}}'
```

---

## 7. 정적 수집(cohort-free) — FIM + 명령 로깅

`fim_change`/`command_ran` 질의가 가능하도록 6v6 의 Wazuh 수집을 **모든 학생 동일하게
정적으로** 켠다(per-task/per-cohort 동적 config 없음).

- **FIM (syscheck, realtime + report_changes + whodata)** — `web`(apache/modsec 설정 + /home/ccc),
  `fw`(/etc/nftables.conf + /etc/haproxy + /home/ccc), `ips`(/etc/suricata + /home/ccc).
  각 컨테이너 `entrypoint.sh` 가 `<ossec_config>` 에 `6v6-assessor-collection` 블록을 1회 주입(멱등).
- **명령 로깅** — 모든 대화형 셸이 `/etc/profile.d/6v6-cmdlog.sh` 의 `PROMPT_COMMAND` 로
  `CMD6V6 host=… user=… pwd=… rc=… cmd=…` 라인을 남긴다.
  - `attacker`/`bastion`(Wazuh agent 없음): 기존 `rsyslog *.* @siem:514` 로 manager 전달.
  - `web`/`fw`/`ips`(Wazuh agent 보유): `/var/log/6v6-cmd.log` localfile 로 manager 전달.
  - manager 의 `cmdlog` decoder/rules(`siem/cmdlog-*.xml`, cont-init `94-cmdlog-rules`)가
    `data.command` 등으로 파싱 → `alerts.json` 기록 → `command_ran`·`/activity` 질의 가능.

> **auditd execve 레이어(검토 후 미채택) — 정직한 기록.**
> 설계상 명령 수집을 "PROMPT(셸 빌트인 포함) + auditd execve(위변조 강함)" 두 겹으로
> 두려 했으나, **Linux audit netlink 는 네임스페이스화되어 있지 않아** 비특권 컨테이너에서
> 접근이 막힌다. `--cap-add AUDIT_CONTROL --cap-add AUDIT_WRITE` 를 줘도 `auditctl` 이
> `Operation not permitted` 로 룰 로드에 실패함을 실측 확인했다. 동작시키려면 fw/ips/web/
> attacker/bastion 을 `--privileged` 로 올려야 하는데, 이는 **보안 실습 인프라에 위험 표면을
> 신설하지 않는다**는 불변식에 정면으로 위배된다. 따라서 auditd 는 채택하지 않고 PROMPT 경로를
> 명령 수집의 단일·검증된 경로로 쓴다. 다만 `/activity` 의 `commands` 핸들러는 auditd 알림
> 형태(`data.audit.command`)도 그대로 파싱하도록 두어, 향후 audit 가능 호스트에선 자동 병합된다
> (`source: prompt|auditd`).

> **bastion 무변경 보장:** 위 셸 profile.d 드롭인은 Bastion 의 두뇌(KG/Manager/SubAgent)·
> API(`/health`·`/exec`·`/chat`)·ProxyJump 와 완전히 무관하다. 명령 합성 surface(`/exec`
> 화이트리스트)는 확장하지 않았고, Assessor 는 Bastion 과 별개 서비스다.

---

## 8. 보안 노트

- `docker.sock` 은 root 등가다. 그래서 CC 문자열을 절대 그대로 실행하지 않고, **고정 템플릿 +
  화이트리스트**로만 명령을 합성한다(`assessor/checks/base.py`, `host.py`). 새 RCE 표면 없음.
- 기존 Bastion `/exec` 화이트리스트는 확장하지 않았다.
- 모든 외부 접근은 **읽기 전용 + API 키**. 쓰기/변경/공격 명령 type 은 존재하지 않는다.
- 보안 핵심 로직은 `assessor/tests/test_checks.py` 로 단위 검증(주입 차단·미지원 거부·필터):
  `python3 -m unittest assessor.tests.test_checks -v` (repo 루트).

---

## 9. cross-infra 듀얼 — VM ↔ VM 도달성 (6v6 측 점검)

tubewar 가 "학생 A 가 학생 B 의 VM 을 공격"하는 cross-infra 듀얼을 운영한다. 6v6 측 결론:

**기존 외부 노출 모델을 그대로 사용한다 — 새 노출 포트를 신설하지 않는다.** 한 VM 의 외부
표면이 곧 VM↔VM 공격 표면이다:

| 외부 노출(VM_IP) | 컨테이너 | cross-infra 용도 |
|------------------|----------|------------------|
| `80`, `443` | fw HAProxy | 상대 취약웹/랜딩 공격(Host 헤더로 vhost 라우팅) |
| `9100` | fw → bastion API | 상대 Bastion API |
| `2204` | bastion SSH | 상대 점프 호스트 |
| `2202` | attacker SSH | 상대 attacker 직접 |

**공격자 두 종류(2026-06):** `attacker`(ext, **insider** — 내부 발판)와 `attacker-ext`(wan,
**outsider** — 내부 브리지 차단, 공개 포트로만). outsider 는 solo 에서도 duel 과 동일한 외부
진입 경로(`<VM_IP>` 공개 포트)를 갖는다. Assessor targets 에 `attacker`/`attacker-ext`(별칭
`insider`/`outsider`) 둘 다 등록 — CC 가 양쪽을 `/assess`·`/activity` 로 질의 가능.

방어선이 **VM 간에도 동일하게** 성립함을 점검·확인:
- A 의 `attacker` → B 의 `VM_IP:80`(`Host: juice.6v6.lab` 등) → **B 의 fw → ips(Suricata) →
  web(ModSecurity) 강제 경유** 후에야 취약웹 도달. 즉 cross-VM 공격도 B 의 IPS/WAF 검사를 받는다.
- B 의 `int`(취약웹 7종, 10.20.40.0/24)은 **직접 노출 없음** — B 의 web vhost reverse proxy 로만
  도달(호스트에서 `docker port 6v6-juiceshop` 없음으로 확인). 따라서 A 는 B 의 내부망에 직접 못 들어간다.
- Assessor(10.20.32.55)는 dmz 내부 서비스로 **별도 published 포트가 없다.** CC 는 `VM_IP:80` 에
  `Host: assessor.6v6.lab` + `X-API-Key` 로만 접근(공격자에겐 의미 없는 읽기 전용 API).

**전제(범위 밖):** CC(중앙) → 학생 VM IP 인바운드 도달은 실습망 기준 가능으로 가정한다. 학생 VM 이
NAT 뒤라 안 닿는 환경은 별도 push 방식이 필요하지만, 본 레포의 책임은 "읽기 전용 표면 제공"까지다.

---

## 10. 미션별 동적 탐지/경보 룰 — 세 경로 (§8)

Wazuh 탐지룰은 manager(siem)에서만, Suricata 룰은 ips 에서 평가된다. "미션에 따른 동적
탐지/경보"는 셋으로 정리하며 **기본은 1번**이다.

1. **check-spec 온디맨드(권장 · 추가 인프라 0)** — 미션별 탐지 로직은 tubewar 가 컴파일하고
   Assessor 가 `wazuh_alert`/`fim_change`/`command_ran`/`log_contains` 로 질의해 판정한다.
   학생 VM 에 룰을 미리 심지 않고도 "이 미션에서 이런 일이 일어났나"를 평가 → decoupling 유지.
   6v6 는 §7 정적 수집만으로 충족, **별도 작업 없음.**
2. **학생 작성 룰(blue 미션)** — 학생이 직접 Suricata 룰(`sid≥9000000` 슬롯) 또는 Wazuh
   local rule 을 작성하는 미션은, 그 룰 파일을 `file_contains` 로 + 실제 발화를 `wazuh_alert`
   로 채점. **6v6 추가 변경 불필요.**
3. **(옵션) 플랫폼 룰 무장(기본 OFF)** — §11 provisioner. read-only 원칙을 깨는 유일한 경로라
   기본 비활성.

## 11. (옵션) 룰 무장 provisioner — `/provision-rule` (기본 OFF)

특정 미션에서 학생 Wazuh 가 특정 행위를 **실시간 탐지**하도록 룰을 미리 무장해야 할 때만 쓰는,
**Assessor 와 분리된 별도 write 서비스**. read-only 원칙의 유일한 예외라 **기본 비활성**이다.

| 항목 | 값 |
|------|----|
| 컨테이너 | `6v6-provisioner` (dmz `10.20.32.56`, profile `provisioner`) |
| 기동 | **기본 OFF.** `SKIP_PROVISIONER=0 bash 6v6.sh up` 으로만. (외부: `provisioner.6v6.lab`) |
| 인증 | `X-API-Key` |
| 안전장치 | named 템플릿 화이트리스트만 · sid 슬롯 `110000–119999` 자동 할당 · 전용 파일 `zz-6v6-provisioned-rules.xml` 하나만 write(다른 룰/디코더 불변) · **반영 전 `wazuh-analysisd -t` 검증 → 실패 시 롤백**(잘못된 룰이 manager 를 못 깨뜨림) |

엔드포인트:
- `GET /health` → `{templates, active_sids, ...}`
- `POST /provision-rule {template, params}` → 룰 무장, 할당된 `sid` 반환
- `POST /revoke-rule {sid}` → 회수(마지막 룰이면 파일 삭제)

템플릿(화이트리스트):
| template | params | 효과 |
|----------|--------|------|
| `alert_command_pattern` | `label`, `pattern`(pcre2), `level?` | cmdlog 명령이 패턴 매칭 시 경보(MY `100260` 위) |
| `alert_fim_path` | `label`, `path_pattern`(pcre2), `level?` | syscheck FIM 경로 매칭 변경 시 경보 |

예시:
```bash
KEY=ccc-api-key-2026
PROV="curl -s -H Host:provisioner.6v6.lab -H X-API-Key:$KEY -H Content-Type:application/json -X POST http://<VM_IP>"
# 무장: 'secret_exfil' 명령 탐지(level 12)
$PROV/provision-rule -d '{"template":"alert_command_pattern","params":{"label":"mission-exfil","pattern":"secret_exfil","level":12}}'
# → {"provisioned":true,"sid":110000,...}
# 회수
$PROV/revoke-rule -d '{"sid":110000}'
```

> **트레이드오프(문서화):** provisioner 는 manager 내부 룰셋에 결합되고 상태(무장된 sid)를
> 가지므로 read-only 모델을 벗어난다. 그래서 ① 기본 OFF, ② 템플릿 화이트리스트만, ③ 전용 파일
> 격리 + 검증·롤백, ④ tubewar 가 미션 시작 시 무장·종료 시 회수하는 운영을 전제로 한다. DoD 필수 아님.
