---
name: purple-team-validation
description: "퍼플팀 탐지 검증 팀 하네스 — 범위→탐지 배포(검증)→통제 공격(검증)→갭 분석 보고. 통제망·승인 필수. 트리거 - '퍼플팀', '탐지 검증', '탐지 우회 검증', 'purple team', 'detection validation'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 2
---

# purple-team-validation

탐지/차단 룰을 배포하고 통제된 공격으로 실제 발현 여부를 검증해 탐지 갭을 보고한다.
공격 모의 → **통제망 + 승인 필수**(red-team-operator 는 attack 티어).

## workflow

```yaml
concurrency_cap: 2
phases:
  - id: 0
    name: 범위
    goal: 검증 대상 TTP·자산 산정
    tasks:
      - task_id: p-scope
        persona: soc-triage-analyst
        name: 범위 산정
        instruction: "검증할 TTP/시나리오와 대상 자산, 통제 경계를 정리한다(scope)."
        output_key: scope
  - id: 1
    name: 탐지 배포
    goal: 대상 TTP 탐지 룰 배포
    tasks:
      - task_id: p-detect
        persona: detection-engineer
        name: 탐지 룰 배포
        instruction: "검증 대상 TTP 에 대한 Suricata/Wazuh/ModSec 탐지 룰을 배포·확인한다."
        output_key: detections
        depends_on: [p-scope]
        verify:
          enabled: true
          criteria:
            - "각 대상 TTP 에 대응 룰이 있는가"
            - "배포 후 룰이 활성/로드되었는가"
            - "오탐 위험이 평가되었는가"
          max_retries: 2
          verifier_persona: soc-lead
  - id: 2
    name: 통제 공격
    goal: 통제된 공격으로 탐지 발현 유도
    tasks:
      - task_id: p-attack
        persona: red-team-operator
        name: 통제 공격
        instruction: "통제 경계 내에서 대상 TTP 를 모의 실행하고 각 시도의 시각/대상/결과를 기록한다."
        output_key: attack
        depends_on: [p-detect]
        verify:
          enabled: true
          criteria:
            - "공격이 통제 경계를 벗어나지 않았는가"
            - "각 시도에 탐지/차단 발현 여부가 기록되었는가"
            - "미탐지(우회) 항목이 명시되었는가"
          max_retries: 1
          verifier_persona: soc-lead
  - id: 3
    name: 보고
    goal: 탐지 갭 통합 보고
    tasks:
      - task_id: p-report
        persona: soc-lead
        name: 갭 분석 보고
        instruction: "detections/attack 를 대조해 탐지된 TTP·미탐지(갭)·개선 룰 권고를 통합 보고한다."
        output_key: report
        depends_on: [p-attack]
```
