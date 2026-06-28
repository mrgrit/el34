---
name: infra-onboarding
description: "신규/미지 인프라 온보딩 팀 하네스 — 자산 인벤토리→(노출·모니터링·기준 병렬)→베이스라인 보고. 읽기 전용. 트리거 - '인프라 온보딩', '인프라 파악', '자산 인벤토리', '신규 인프라 점검', 'onboarding', 'baseline'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 3
---

# infra-onboarding

처음 보는 환경의 자산을 파악하고 노출면·모니터링 가용성·기준 준수를 베이스라인으로 점검한다(읽기 전용).
discovery(`/discover`)와 병행하면 좋다.

## workflow

```yaml
concurrency_cap: 3
phases:
  - id: 0
    name: 인벤토리
    goal: 자산·서비스 식별
    tasks:
      - task_id: o-inventory
        persona: soc-triage-analyst
        name: 자산 인벤토리
        instruction: "도달 가능한 호스트/서비스를 탐지(probe_all/probe_host)해 자산 인벤토리를 작성한다."
        output_key: inventory
  - id: 1
    name: 베이스라인
    goal: 노출 + 모니터링 + 기준 병렬 점검
    max_concurrency: 3
    tasks:
      - task_id: o-exposure
        persona: vuln-asset-manager
        name: 노출면
        instruction: "인벤토리 자산의 외부 노출 포트/웹 서비스를 점검해 공격면을 요약한다."
        output_key: exposure
        depends_on: [o-inventory]
      - task_id: o-monitoring
        persona: siem-log-analyst
        name: 모니터링 가용성
        instruction: "SIEM/IDS 모니터링이 자산을 실제로 커버하는지(에이전트/로그 수집) 점검한다."
        output_key: monitoring
        depends_on: [o-inventory]
      - task_id: o-baseline
        persona: compliance-auditor
        name: 기준 베이스라인
        instruction: "핵심 자산의 기준(CIS) 준수·시크릿 노출 베이스라인을 점검한다."
        output_key: baseline
        depends_on: [o-inventory]
  - id: 2
    name: 보고
    goal: 온보딩 베이스라인 보고
    tasks:
      - task_id: o-report
        persona: soc-lead
        name: 온보딩 보고
        instruction: "inventory/exposure/monitoring/baseline 을 통합해 인프라 베이스라인과 모니터링 갭·우선 조치를 보고한다."
        output_key: report
        depends_on: [o-exposure, o-monitoring, o-baseline]
```
