# Bastion Harness Engineering

> 📖 상황별 구성 레시피는 [`COOKBOOK.md`](./COOKBOOK.md) — 인시던트/헌팅/취약점/온보딩/커스텀 등.
>
> bastion 의 **다중 페르소나 SOC 팀 오케스트레이션**. 단일 에이전트가 스킬 하나씩 처리하던
> 방식을, 전문 페르소나 팀이 단계(phase)별로 협업하며 검증까지 거치는 방식으로 확장한다.
> revfactory/harness-engineering-with-cc 방법론을 bastion 의 main-subagent 구조에 맞춰 수용.

---

## 1. 개념 — "하네스(harness)"란

**하네스 = 미리 정의된 작업환경.** "대화를 잘 굴리는" 대신, 작업 전에 *누가(페르소나) ·
무엇을(도구 경계) · 어떤 순서로(단계/의존) · 어떻게 검증하며* 일할지를 미리 세팅해 둔다.

bastion 적용의 두 가지 핵심 결정:

| 결정 | 의미 |
|------|------|
| **페르소나 = 논리적 서브에이전트** | 페르소나는 매니저(bastion) 측의 "역할(모자)"이다. **기계(컨테이너)에 묶이지 않는다.** "1 컨테이너 = 1 서브에이전트"(옛 모델)는 40+ 컨테이너에선 성립 불가 → 폐기. |
| **컨테이너 = 자산(asset)** | 페르소나는 컨테이너를 *대상*으로 다룬다. 실행은 기존 경로(`execute_skill` → `run_command` → `docker exec`/ssh). |

두 갈래가 같은 **HarnessSpec** 을 만들고, 오케스트레이터가 6단계로 실행한다:

```
수동: harness/.bastion/{agents,skills}/*.md + BASTION.md ─┐
                                                          ├─► HarnessSpec ─► orchestrator.run_harness() ─► 6 phase
자동(Phase C, 예정): discovery + Experience Graph ────────┘
```

리더(`soc-lead`)는 **무발화** — 라우팅·통합만 하고, 본문은 워커 페르소나가 생산한다.

---

## 2. 구성 파일

```
bastion/src/
├── packages/bastion/
│   ├── harness.py        # HarnessSpec 데이터모델 + 수동 md 파서 + 검증 + 위상정렬 + KG io
│   ├── orchestrator.py   # run_harness 6단계 엔진 (페르소나 스코프 ReAct, 생성-검증 루프)
│   ├── targets.py        # 역할→컨테이너 해석 (discovery 우선, el34 정적 폴백)  [Phase B]
│   ├── discovery.py      # docker 인프라 자동 발견 + 역할 추론 + 자산 등록        [Phase B]
│   ├── harness_gen.py    # discovery+경험 → 하네스 자동 생성 + 감사 아티팩트       [Phase C]
│   ├── feedback.py       # 실행 성과 누적(KG) → 티어 조정·교훈 주입(자기개선)        [Phase D]
│   └── tests/test_harness.py, test_discovery.py, test_harness_gen.py, test_feedback.py
└── harness/
    ├── generated/<id>/   # 자동 생성 spec + 팀/매트릭스/모델근거/batches (감사용) [Phase C]
    ├── BASTION.md                         # 전역 SOC 규칙 (모든 하네스에 주입)
    ├── .bastion/agents/*.md               # 기본 SOC 페르소나 12종 (8섹션)
    ├── .bastion/skills/<harness>/SKILL.md # 팀 워크플로 8종 (incident/hunt/vuln/compliance/ai/purple/forensics/onboarding)
    └── workspace/<run_id>/                # 실행별 산출물(보존, gitignore)
```

> 브랜딩: Claude 컨벤션(`.claude/`, `CLAUDE.md`) 대신 bastion 컨벤션(`.bastion/`, `BASTION.md`) 사용.

---

## 3. 데이터 모델 (`harness.py`)

```
HarnessSpec
  harness_id, name, description, source(manual|auto|hybrid)
  rules[]            ← BASTION.md
  concurrency_cap=4
  team: [Persona]
  phases: [Phase]
  triggers[]         ← 자연어 라우팅 트리거

Persona
  role, description(트리거)
  model_tier: reasoning | execution | attack   ← 모델 배정
  allowed_skills[]   ← ⊆ SKILLS 키 (== 도구 경계, 물리적 강제)
  can_write          ← False면 danger/승인필요 스킬 차단(읽기 전용)
  active_phases[]
  prompt{ core_role, work_principles, io_protocol, error_handling,
          collaboration, team_comms, reinvocation, quality_self_check }  ← 8섹션

Phase { id, name, goal, max_concurrency, tasks:[Task] }
Task  { task_id, persona, name, instruction, output_key,
        depends_on[],                          ← DAG (위상정렬 → 배치)
        verify{ enabled, criteria[], max_retries, verifier_persona } }
```

**모델 티어 → 실제 모델** (`resolve_model`): `reasoning→LLM_MANAGER_MODEL`(gpt-oss:120b),
`execution→LLM_SUBAGENT_MODEL`(qwen3:8b), `attack→LLM_MANAGER_MODEL_UNSAFE`.

**KG 영속화**: 노드 `Persona`/`Harness`, 엣지 `member_of`/`uses`/`specializes_in` (graph.py 가산).

---

## 4. 수동 하네스 작성

### 4.1 페르소나 — `.bastion/agents/<role>.md`
frontmatter + 8섹션 본문:
```markdown
---
name: incident-responder
description: "...트리거 - '격리', '봉쇄', 'containment'."
model: reasoning            # reasoning|execution|attack (opus→reasoning, sonnet/haiku→execution 별칭 허용)
tools: forensic_collect, memory_dump, process_kill, configure_nftables, ioc_export   # ⊆ SKILLS
can_write: true
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

### 4.2 팀 워크플로 — `.bastion/skills/<harness>/SKILL.md`
frontmatter + `## workflow` YAML(정확한 DAG):
```markdown
---
name: incident-response-team
description: "...트리거 - '인시던트 대응', '알림 조사하고 차단', ..."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
---
## workflow
```yaml
concurrency_cap: 4
phases:
  - id: 0
    name: 트리아지
    tasks:
      - task_id: t-triage
        persona: soc-triage-analyst
        instruction: "..."
        output_key: triage
  - id: 2
    tasks:
      - task_id: t-contain
        persona: incident-responder
        depends_on: [t-hunt, t-timeline]
        verify:
          enabled: true
          criteria: ["차단 범위 한정", "증거 보존", "변경 확인"]
          max_retries: 2
          verifier_persona: soc-lead       # 검증자 ≠ 생산자(강제)
```
```
`## workflow` YAML 이 없으면 SOC 라이프사이클 템플릿으로 폴백.

### 4.3 전역 규칙 — `BASTION.md`
`- ` 불릿이 규칙으로 파싱되어 모든 하네스에 주입(무발화 리더·검증자≠생산자·승인 게이트 등).

---

## 5. 기본 SOC 페르소나 12종

| role | tier | write | 핵심 skill |
|------|------|-------|-----------|
| `soc-lead` (무발화 오케스트레이터/통합) | reasoning | ✗ | history_anchor, ioc_export |
| `soc-triage-analyst` | execution | ✗ | probe_*, check_suricata/wazuh/modsecurity |
| `threat-hunter` | reasoning | ✗ | analyze_logs, scan_ports, dns_recon, cve_lookup |
| `incident-responder` | reasoning | ✓ | forensic_collect, process_kill, configure_nftables |
| `detection-engineer` | reasoning | ✓ | deploy_rule, wazuh_api, check_* |
| `siem-log-analyst` | execution | ✗ | check_wazuh, wazuh_api, analyze_logs |
| `network-firewall-analyst` | reasoning | ✓ | configure_nftables, scan_ports |
| `vuln-asset-manager` | execution | ✗ | scan_ports, web_scan, cve_lookup, compliance_scan |
| `forensics-malware-analyst` | reasoning | ✓ | forensic_collect, memory_dump, ioc_export |
| `ai-security-analyst` | reasoning | ✓ | prompt_fuzz, garak_probe, model_isolate |
| `compliance-auditor` | execution | ✗ | compliance_scan, secret_scan |
| `red-team-operator` (퍼플팀 검증) | attack | ✓ | attack_simulate, password_attack |

기본 워크플로 **8종**(`.bastion/skills/`): `incident-response-team`(트리아지→조사→봉쇄·탐지(검증)→보고),
`threat-hunt-team`(범위→병렬 헌팅→룰화), `vuln-assessment-team`(취약점·컴플라 병렬),
`compliance-audit-team`(CIS·시크릿/감사로그), `ai-security-team`(적대평가→격리(검증)),
`purple-team-validation`(탐지배포→통제공격, 둘 다 검증), `forensics-investigation-team`(수집·분석 검증),
`infra-onboarding`(인벤토리→노출·모니터링·기준 베이스라인). 상황별 사용법은 [`COOKBOOK.md`](./COOKBOOK.md).

---

## 6. 6단계 오케스트레이션 (`orchestrator.run_harness`)

| Phase | 동작 |
|-------|------|
| **P0 입력** | 요청 + KG 컨텍스트 수집. `harness_start` 이벤트. |
| **P1 팀 생성** | 논리 페르소나 활성(컨테이너 없음). 페르소나별 scratchpad + 스코프 컨텍스트 + 도구 경계. |
| **P2 위상 배치** | `depends_on` DAG → 위상정렬 배치(동시 시작 가능 묶음). |
| **P3 fan-out** | 배치별 동시 실행(≤ concurrency_cap). 각 태스크 = **페르소나 스코프 ReAct**: persona 8섹션 프롬프트 + `allowed_skills` 로 필터된 도구 + `execute_skill`. 승인/위험/precheck 는 기존 agent 헬퍼 재사용. |
| **P4 생성-검증** | verify 게이트 태스크는 **검증자(읽기전용)** 가 기준 판정 → 실패면 피드백 반영 재생성(≤max_retries) → 소진 시 `escalate`. |
| **P5 통합** | `soc-lead` 가 P0/P1/P2 우선순위로 통합 보고. KG(`kg_recorder`)·Experience 기록. `harness_done`. |

**도구 경계·승인 강제**: 페르소나가 `allowed_skills` 밖 도구를 호출하면 차단(`boundary_block`).
읽기 전용 페르소나가 danger/승인필요 스킬을 호출해도 차단. 승인 거부 시 `skill_skip`(상태 무변경).

**이벤트 스트림**(NDJSON): `harness_start, persona_activate, plan, phase_start, task_create,
task_start, skill_start, skill_result, risk_warning, skill_skip, boundary_block, verify_start,
verify_result, escalate, task_done, harness_done`.

---

## 7. 범용화 — 인프라 발견 & 타깃 해석 (Phase B)

bastion 을 특정 배포(el34)에 묶지 않기 위해:

- **`discovery.py`** — 부팅 시(또는 `POST /discover`) `docker ps` 로 인프라를 스캔하고
  이름/이미지 휴리스틱(`infer_role`)으로 **역할→컨테이너 매핑**을 만든다. 컨테이너는
  자산으로 KG(`asset_domain`)에 등록된다.
- **`targets.py`** — 스킬은 `container_for('ids')` 처럼 **역할**로 대상을 가리킨다.
  해석 우선순위: ① `BASTION_DISCOVERY=1` + 발견 매핑 → 발견 컨테이너,
  ② 그 외 → **정적 el34 폴백**(`STATIC_CONTAINERS`).
- **무회귀**: `BASTION_DISCOVERY` 미설정 시 정적 폴백 → 기존 el34 동작과 100% 동일.
  설정 시에도 el34 에선 발견 매핑이 정적 폴백과 일치(검증됨) → 안전.

`skills.py` 의 하드코딩 `docker exec el34-*` 5곳(scan_ports/check_suricata/check_wazuh/
check_modsecurity/configure_nftables)은 `container_for(role)` 로 대체됨.

---

## 8. API

| 메서드/경로 | 설명 |
|---|---|
| `POST /harness/run` | 하네스 6단계 실행 — NDJSON 스트림. `{message, harness_id?, auto_approve, approval_mode, course, stream}`. `harness_id` 비우면 트리거 자동매칭. |
| `POST /harness/generate` | dry-run — 하네스 spec 로드/생성+검증만(JSON). `auto:true` → discovery+경험 자동 생성. |
| `GET /harness/list` | 사용 가능한 하네스 목록. |
| `GET /personas` | 기본 SOC 페르소나 라이브러리. |
| `POST /discover` | 인프라 재스캔 → 역할맵+자산. |
| `GET /infra-map` | 현재 발견 매핑 + discovery 활성 여부. |

자동 라우팅: `/chat` 메시지가 하네스 트리거에 맞으면 `_should_use_harness` 가 팀 경로로
보낸다(아니면 기존 단일 스킬 경로 유지). `BASTION_HARNESS_AUTO=0` 으로 비활성 가능.

### 사용 예
```bash
# 자동 매칭 + 실행 (auto_approve=false → 쓰기 스킬은 승인 대기/거부 → 인프라 무변경)
curl -sN -X POST http://<bastion>:9100/harness/run -H 'Content-Type: application/json' \
  -d '{"message":"siem 알림 조사하고 차단까지","auto_approve":false}'

# dry-run (실행 없이 spec 확인)
curl -s -X POST http://<bastion>:9100/harness/generate -H 'Content-Type: application/json' \
  -d '{"harness_id":"incident-response-team","message":"x"}'

# 자동 생성 (discovery+경험으로 인프라 맞춤 하네스 — 수동 md 불필요)
curl -s -X POST http://<bastion>:9100/harness/generate -H 'Content-Type: application/json' \
  -d '{"message":"인프라 보안 점검하고 위협 대응","auto":true}'
curl -sN -X POST http://<bastion>:9100/harness/run -H 'Content-Type: application/json' \
  -d '{"message":"인프라 보안 점검하고 위협 대응","auto":true,"auto_approve":false}'

# 인프라 발견
curl -s -X POST http://<bastion>:9100/discover
```

---

## 9. 환경변수

| 변수 | 기본 | 설명 |
|------|------|------|
| `LLM_MANAGER_MODEL` | gpt-oss:120b | reasoning 티어 모델 |
| `LLM_SUBAGENT_MODEL` | qwen3:8b | execution 티어 모델 |
| `LLM_MANAGER_MODEL_UNSAFE` | — | attack 티어 모델 |
| `BASTION_HARNESS_AUTO` | 1 | `/chat` 트리거 자동 라우팅(0=비활성) |
| `BASTION_HARNESS_MAX_TURNS` | 4 | 페르소나 태스크당 ReAct turn 상한 |
| `BASTION_DISCOVERY` | 0 | 1=발견 매핑을 타깃 해석에 사용(범용 모드) |
| `BASTION_HARNESS_DIR` | `<src>/harness` | 하네스 콘텐츠 루트 override |
| `BASTION_HARNESS_FORCE_FAIL` | — | (테스트) 지정 task_id 검증 강제 실패 |

---

## 10. 테스트

```bash
PYTHONPATH=/opt/ccc-src:/opt/ccc-src/packages \
  python3 -m unittest bastion.tests.test_harness bastion.tests.test_discovery
```
파싱/검증(DAG·검증자≠생산자·도구경계)/위상정렬/오케스트레이터(순서·검증 escalation)/
타깃 해석 무회귀/역할 추론/발견 파싱 — 총 18 케이스(LLM 불필요, mock).

---

## 11. 로드맵

- **Phase A (완료)** — HarnessSpec + 수동 md + 6단계 오케스트레이터 + 기본 SOC 페르소나.
- **Phase B (완료)** — 인프라 Discovery + 타깃 해석(el34 하드코딩 제거, 범용화).
- **Phase C (완료)** — `harness_gen.py`: discovery(present 자산역할) + Experience(get_context) →
  **하네스 자동 생성**(페르소나 선택·모델티어·SOC 라이프사이클 DAG·verify 게이트, 결정론).
  인프라에 적응(예: 모델 자산 없으면 ai-security-analyst 자동 제외). 감사 아티팩트
  (`harness/generated/<id>/00_team_table.md`·`01_phase_matrix.md`·`03_model_rationale.md`·
  `batches.json`·`spec.json`) 생성. (옵션 `bind_playbooks` 로 승격 playbook 바인딩.)
- **Phase D (완료)** — `feedback.py`: 실행 결과를 KG Persona meta(runs/success_rate/pitfalls)에
  누적하는 **자기개선 루프**. 다음 자동 생성 시 `apply_feedback` 로 (1) 과거 실패 교훈을 페르소나
  `quality_self_check` 에 주입, (2) success_rate 기반 모델 티어 조정(검증된 읽기전용 reasoning→
  execution 경량화 / 저성과 execution→reasoning + verify 강제). orchestrator 가 verify 강화
  (빈 산출물 objective fail) + 옵션 매니저 LLM 정제(`BASTION_HARNESS_LLM_REFINE`).
  `GET /personas` 가 성과(stats) 노출.

---

## 12. 트러블슈팅

- **하네스가 안 뜸**: `GET /harness/list` 로 트리거 확인 → 메시지가 트리거에 매칭되는지.
  명시적으로 `harness_id` 지정 가능. `BASTION_HARNESS_AUTO=0` 이면 자동 라우팅 꺼짐.
- **검증 무한 escalate**: verify `criteria` 가 너무 엄격하거나, 쓰기 스킬 승인 거부로 실제
  조치가 안 됨(`auto_approve=false`) → 의도된 동작. 실제 조치하려면 승인 모드/auto_approve.
- **엉뚱한 컨테이너 타깃**: `GET /infra-map` 으로 역할맵 확인. el34 외 인프라면
  `BASTION_DISCOVERY=1` 후 `POST /discover`. 추론 오류 시 `targets.STATIC_CONTAINERS` 보강.
- **LLM 동시성**: 단일 Ollama 백엔드는 모델 스왑을 직렬화 → 페르소나 병렬 호출이 큐잉될 수
  있다(정확성엔 무관, 느려짐). `concurrency_cap`/`max_concurrency` 로 조절.
