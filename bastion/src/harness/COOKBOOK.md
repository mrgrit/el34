# 상황별 Harness 구성 매뉴얼 (Cookbook)

> SOC 상황별로 어떤 harness 를 어떻게 구성·실행할지 정리한 실전 레시피.
> 개념·데이터모델·전체 레퍼런스는 [`README.md`](./README.md) 참조.
> `<B>` = bastion 호스트:포트 (예: `192.168.0.161:9100` 또는 컨테이너 `127.0.0.1:9100`).

---

## 0. 먼저 — 3가지 구성 방식

| 방식 | 언제 | 어떻게 |
|------|------|--------|
| **A. 수동 하네스** (manual) | 정형화된 반복 작업(인시던트 대응·헌팅). 절차를 고정하고 싶을 때 | `.bastion/skills/<id>/SKILL.md` 작성 → 트리거 또는 `harness_id` 로 실행 |
| **B. 자동 생성** (auto) | 인프라/요청에 맞춰 팀을 매번 새로 짜고 싶을 때. 미지 인프라 | `{"auto": true}` → discovery+경험으로 하네스 합성 |
| **C. 단일 스킬** (`/chat`) | 빠른 단건 점검·질의 (팀 불필요) | 기존 `/chat` — 트리거 미매칭 메시지는 자동으로 이 경로 |

**선택 기준 한 줄 요약**
- "이 절차를 매번 똑같이" → **A 수동**
- "이 인프라/요청에 맞게 알아서" → **B 자동**
- "이거 하나만 빨리" → **C 단일**

```
요청 ─► 트리거 매칭? ─예─► 수동 하네스(A)
        └─아니오─► auto:true ? ─예─► 자동 생성(B)
                    └─아니오─► 단일 스킬 /chat (C)
```

---

## 1. 공통 운영 노브 (모든 시나리오 공통)

| 파라미터/환경변수 | 효과 | 권장 |
|---|---|---|
| `auto_approve` (요청 body) | true=고위험(쓰기) 스킬 자동 승인 → **실제 인프라 변경** / false=거부(점검·드라이) | **점검은 false**, 실제 대응만 true |
| `approval_mode` | `normal`/`danger_danger`/`danger_danger_danger` 승인 강도 | normal |
| `course` | 공격/대전 코스면 derestricted 모델 라우팅 | 일반 SOC 는 공란 |
| `BASTION_HARNESS_AUTO` | `/chat` 의 트리거 자동 라우팅(0=끔) | 1 |
| `BASTION_DISCOVERY` | 1=발견 매핑으로 타깃 해석(범용) / 0=el34 정적 폴백 | 비-el34 인프라면 1 |
| `BASTION_HARNESS_MAX_TURNS` | 페르소나 태스크당 ReAct turn 상한 | 4 (느리면 ↓) |
| `BASTION_HARNESS_LLM_REFINE` | 1=생성 spec 을 매니저 LLM 으로 정제 | 품질 우선 시 1 |
| `concurrency_cap` (spec) | 동시 활성 페르소나 상한 | 4 (단일 LLM 백엔드면 ↓) |

> **안전 원칙**: 처음 보는 환경/실습은 `auto_approve:false` 로 시작 → 읽기 스킬만 실행되고 쓰기(차단/룰배포)는 승인 게이트에서 막힌다(인프라 무변경). 검증 후 실제 대응 시 true.

---

## 2. 시나리오별 레시피

### S1. SIEM 알림 → 인시던트 대응 (가장 흔함)
- **목표**: 알림 조사 → 위협 확인 → 차단·격리 → 탐지룰 → 보고
- **권장**: A 수동 `incident-response-team` (정형 절차)
- **팀**: soc-triage-analyst → (siem-log-analyst, threat-hunter) → (incident-responder, detection-engineer) → soc-lead
- **실행**
  ```bash
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"message":"siem 알림 조사하고 차단까지","auto_approve":false}'
  # auto_approve:false → 조사는 실행, 차단/룰배포는 승인 대기(검증). 실제 대응이면 true.
  ```
- **트리거**(메시지에 포함되면 `/chat` 에서도 자동): `인시던트 대응`·`침해 대응`·`알림 조사하고 차단`·`격리 대응`
- **기대**: 6단계 스트림(harness_start→…→harness_done) + P0/P1/P2 우선순위 통합 보고. 봉쇄/탐지는 verify 게이트(미흡 시 재시도→escalate).

### S2. 위협 헌팅 (능동 탐색)
- **목표**: 가설 기반 IoC/TTP 탐색 → 룰화 → 보고
- **권장**: A 수동 `threat-hunt-team`
- **팀**: soc-triage-analyst(범위) → (threat-hunter, siem-log-analyst, vuln-asset-manager) → (detection-engineer, soc-lead)
- **실행**
  ```bash
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"message":"위협 헌팅 — 최근 외부 C2 비콘 흔적 찾아줘","auto_approve":false}'
  ```
- **트리거**: `위협 헌팅`·`threat hunt`·`침해 흔적 탐색`·`능동 탐색`

### S3. 취약점·자산 점검
- **목표**: 노출 서비스·CVE 식별, 우선순위화 (읽기 전용)
- **권장**: A 전용 하네스 **`vuln-assessment-team`** (범위→취약점·컴플라 병렬→보고) / 또는 `auto`
- **팀**: soc-triage-analyst → (vuln-asset-manager, compliance-auditor) → soc-lead
- **실행**
  ```bash
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"harness_id":"vuln-assessment-team","message":"전체 노출 서비스·CVE 점검하고 우선순위 보고","auto_approve":false}'
  ```
- **트리거**: `취약점 평가`·`노출 점검`·`자산 점검` (auto 매칭도 가능)

### S4. 컴플라이언스 감사
- **목표**: CIS/시크릿/감사로그 미준수 점검 (읽기 전용)
- **권장**: A 전용 하네스 **`compliance-audit-team`** (범위→CIS·시크릿 / 감사로그 병렬→보고) / 또는 `auto`
- **팀**: soc-triage-analyst → (compliance-auditor, siem-log-analyst) → soc-lead
- **실행**
  ```bash
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"harness_id":"compliance-audit-team","message":"보안 기준 준수·시크릿 노출 감사","auto_approve":false}'
  ```
- **트리거**: `컴플라이언스 감사`·`보안 기준 점검`·`CIS 점검`

### S5. AI/모델 보안 점검 (Ollama 등 모델 자산 있을 때)
- **목표**: 프롬프트 인젝션·jailbreak·RAG 무결성·모델 격리
- **권장**: A 전용 하네스 **`ai-security-team`** (범위→적대평가→격리(검증)→보고) / 또는 `auto`
- **팀**: soc-triage-analyst → ai-security-analyst(평가) → ai-security-analyst(격리, verify) → soc-lead
- **전제**: 모델이 컨테이너로 떠 있어야 의미. `POST /discover` 후 `GET /infra-map` 에 `ai-model` 확인.
  (`auto` 는 모델 자산 없으면 ai-security-analyst 자동 제외 — el34 처럼 LLM 이 외부면 의도된 동작)
- **실행**
  ```bash
  curl -s -X POST http://<B>/discover            # 모델 자산 발견 확인
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"harness_id":"ai-security-team","message":"LLM 서비스 프롬프트 인젝션·RAG 무결성 점검","auto_approve":false}'
  ```
- **트리거**: `AI 보안`·`LLM 보안`·`프롬프트 인젝션`·`RAG 무결성`

### S6. 퍼플팀 — 탐지/차단 검증
- **목표**: 배포된 탐지/차단이 실제 작동하는지 통제 공격으로 검증
- **권장**: A 전용 하네스 **`purple-team-validation`** (범위→탐지배포(검증)→통제공격(검증)→갭보고)
- **팀**: soc-triage-analyst → detection-engineer(verify) → red-team-operator(verify) → soc-lead
- **주의**: 공격 모의 → 통제망 + 승인 필수. attack 티어 라우팅(`course`).
  ```bash
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"harness_id":"purple-team-validation","message":"탐지 룰 배포하고 퍼플팀으로 우회 검증","auto_approve":true,"course":"attack-ai"}'
  ```
- **트리거**: `퍼플팀`·`탐지 검증`·`탐지 우회 검증`

### S7. 신규/미지 인프라 온보딩 (범용 showcase)
- **목표**: 처음 보는 환경을 파악하고 베이스라인 점검 + 인프라 맞춤 팀 자동 구성
- **권장**: 전용 하네스 **`infra-onboarding`**(인벤토리→노출·모니터링·기준 병렬→베이스라인 보고) +
  대응이 필요하면 `auto`(discovery 로 인프라 맞춤 팀 합성)
- **절차**
  ```bash
  # 베이스라인: 전용 온보딩 하네스
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"harness_id":"infra-onboarding","message":"이 인프라 자산·노출·모니터링 베이스라인","auto_approve":false}'
  ```
- **인프라 맞춤 자동 구성(showcase) 절차**
  ```bash
  # 1) discovery 켜고(BASTION_DISCOVERY=1) 인프라 스캔
  curl -s -X POST http://<B>/discover | jq '.role_map'
  curl -s http://<B>/infra-map
  # 2) 발견된 자산에 맞춰 하네스 자동 생성(dry-run 으로 팀 먼저 확인)
  curl -s -X POST http://<B>/harness/generate -H 'Content-Type: application/json' \
    -d '{"message":"이 인프라 보안 상태 점검하고 위협 대응","auto":true}' | jq '.spec.team[].role, .spec.meta.present_roles'
  # 3) 확인되면 실행
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"message":"이 인프라 보안 상태 점검하고 위협 대응","auto":true,"auto_approve":false}'
  ```
- **기대**: present 자산에 매칭되는 페르소나만 자동 선택(예: 모델 없으면 ai-security 제외, fw 없으면 network/contain 제외). 감사 아티팩트 `harness/generated/soc-auto/`(team_table·phase_matrix·model_rationale·batches.json) 생성.

### S8. 포렌식·침해 분석
- **목표**: 증거 보존·분석·IoC 추출
- **권장**: A 전용 하네스 **`forensics-investigation-team`** (범위→수집(검증)·타임라인→분석·IoC(검증)→보고)
- **팀**: soc-triage-analyst → (forensics-malware-analyst 수집[verify], siem-log-analyst 타임라인) → forensics-malware-analyst 분석[verify] → soc-lead
  ```bash
  curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
    -d '{"harness_id":"forensics-investigation-team","message":"의심 호스트 증거 보존하고 IoC 추출","auto_approve":true}'
  ```
- **주의**: forensic_collect/memory_dump 는 쓰기/수집 → 승인 필요. 휘발성 순서 준수.
- **트리거**: `포렌식`·`침해 분석`·`증거 수집`·`메모리 분석`

### S9. 빠른 단건 점검 (팀 불필요)
- **목표**: "suricata 상태만", "이 IP 포트 스캔" 같은 단발
- **권장**: C 단일 스킬 — 그냥 `/chat`. 트리거 미매칭이라 팀이 안 뜨고 단일 스킬 실행.
  ```bash
  curl -sN -X POST http://<B>/chat -H 'Content-Type: application/json' \
    -d '{"message":"suricata IDS 상태 확인","auto_approve":true}'
  ```

### S10. 커스텀 하네스 작성 (특수 절차 고정)
→ 아래 §3 참조.

---

## 3. 커스텀 하네스 만들기 (3단계)

기존 12 페르소나로 새 팀 절차를 고정하거나, 새 페르소나를 추가한다.

**① (필요 시) 페르소나 추가** — `.bastion/agents/<role>.md` (8섹션):
```markdown
---
name: cloud-security-analyst
description: "클라우드 설정 점검. 트리거 - '클라우드 점검', 'IAM 감사'."
model: reasoning            # reasoning|execution|attack
tools: compliance_scan, secret_scan, http_request   # ⊆ SKILLS 키 (도구 경계)
can_write: false
---
## 핵심 역할
## 작업 원칙
## 입출력 프로토콜
## 에러 핸들링
## 협업 정의
## 팀 통신 프로토콜
## 재호출 지침
## 품질 자체 검증
```

**② 워크플로 작성** — `.bastion/skills/<harness-id>/SKILL.md` 의 `## workflow` YAML:
```markdown
---
name: vuln-assessment-team
description: "취약점 평가 팀. 트리거 - '취약점 평가', '노출 점검'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
---
## workflow
```yaml
concurrency_cap: 3
phases:
  - id: 0
    name: 범위
    tasks:
      - {task_id: v-scope, persona: soc-triage-analyst, output_key: scope,
         instruction: "평가 대상 자산/범위 정리"}
  - id: 1
    name: 평가
    tasks:
      - {task_id: v-vuln, persona: vuln-asset-manager, depends_on: [v-scope], output_key: vuln,
         instruction: "노출 서비스·CVE 식별·우선순위화"}
      - {task_id: v-comp, persona: compliance-auditor, depends_on: [v-scope], output_key: comp,
         instruction: "CIS/시크릿 미준수 점검"}
  - id: 2
    name: 보고
    tasks:
      - {task_id: v-report, persona: soc-lead, depends_on: [v-vuln, v-comp], output_key: report,
         instruction: "위험 우선순위 통합 보고"}
```
```

**③ 검증 + 실행**
```bash
curl -s http://<B>/harness/list                       # 새 하네스 보이는지
curl -s -X POST http://<B>/harness/generate -H 'Content-Type: application/json' \
  -d '{"harness_id":"vuln-assessment-team","message":"x"}' | jq '.valid, .errors'   # 검증
curl -sN -X POST http://<B>/harness/run -H 'Content-Type: application/json' \
  -d '{"harness_id":"vuln-assessment-team","message":"취약점 평가","auto_approve":false}'
```

**작성 규칙(검증기가 강제)**: `depends_on` 은 DAG(순환 금지) · 검증자 ≠ 생산자 · `tools`⊆SKILLS · 동시성 ≤ cap. `verify.enabled` 태스크는 `verifier_persona` 를 **읽기 전용 동료**(예: soc-lead)로.

---

## 4. 페르소나 빠른 참조 (선택 가이드)

| 역할 | tier | write | 쓰임 | 자동선택 조건(자산) |
|------|------|-------|------|---------------------|
| soc-lead | reasoning | ✗ | 무발화 오케스트레이터·통합 | 항상 |
| soc-triage-analyst | execution | ✗ | 초기 분류 | 항상 |
| threat-hunter | reasoning | ✗ | 가설 헌팅 | siem/ids/web |
| siem-log-analyst | execution | ✗ | 로그 상관·타임라인 | siem |
| network-firewall-analyst | reasoning | ✓ | 방화벽 정책 | fw |
| vuln-asset-manager | execution | ✗ | 취약점·CVE | attacker/app/web |
| detection-engineer | reasoning | ✓ | 탐지 룰 배포 | ids/web/siem |
| incident-responder | reasoning | ✓ | 봉쇄·격리 | fw/siem |
| forensics-malware-analyst | reasoning | ✓ | 증거·IoC | 항상 |
| ai-security-analyst | reasoning | ✓ | LLM 보안 | **ai-model** |
| compliance-auditor | execution | ✗ | 기준·시크릿 | 항상 |
| red-team-operator | attack | ✓ | 퍼플 검증 | attacker |

자동 생성은 이 표의 "자산 조건"으로 페르소나를 고른다(`harness_gen.PERSONA_ASSET_REQ`).

---

## 5. 운영 — 성과 확인 & 튜닝 (피드백 루프)

하네스를 돌릴수록 페르소나 성과가 KG 에 쌓이고 자동 생성 품질이 올라간다(Phase D).
```bash
curl -s http://<B>/personas | jq '.personas[] | {role, model_tier, stats}'
# stats.success_rate 높은 읽기전용 페르소나 → 다음 자동생성에서 경량 모델로 자동 전환,
# 실패 잦은 페르소나 → 교훈(pitfalls)이 프롬프트에 주입 + verify 강제.
```
- 생성 spec 품질을 더 높이려면 `BASTION_HARNESS_LLM_REFINE=1` (매니저 LLM 이 instruction/criteria 정제).
- 느리면 `BASTION_HARNESS_MAX_TURNS` ↓ 또는 워크플로 `concurrency_cap` ↓.

---

## 6. 안전 체크리스트
- [ ] 점검/탐색은 `auto_approve:false` 로 (쓰기 스킬은 승인 게이트에서 차단 → 인프라 무변경)
- [ ] red-team-operator/공격 모의는 통제망 + 승인 + `course` 명시
- [ ] 실제 차단/룰배포 전 dry-run(`/harness/generate`)으로 팀·계획 확인
- [ ] 미지 인프라는 `BASTION_DISCOVERY=1` + `/discover` 로 타깃 먼저 확인(`/infra-map`)
- [ ] 산출물은 `harness/workspace/<run_id>/` 에 보존 — 사람 재검토

문제 해결은 [`README.md` §12 트러블슈팅](./README.md) 참조.
