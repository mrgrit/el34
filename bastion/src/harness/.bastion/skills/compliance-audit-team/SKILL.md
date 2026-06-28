---
name: compliance-audit-team
description: "컴플라이언스 감사 팀 하네스 — 범위→(CIS·시크릿 / 감사로그 병렬)→보고. 읽기 전용. 트리거 - '컴플라이언스 감사', '보안 기준 점검', '준수 점검', 'compliance audit', 'CIS 점검'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 3
---

# compliance-audit-team

보안 기준(CIS)·시크릿 노출·감사로그(로깅/보존) 준수를 점검해 미준수 항목과 증거를 보고한다(읽기 전용).

## workflow

```yaml
concurrency_cap: 3
phases:
  - id: 0
    name: 범위
    goal: 감사 대상·기준 산정
    tasks:
      - task_id: c-scope
        persona: soc-triage-analyst
        name: 범위 산정
        instruction: "감사 대상 자산과 적용 기준(CIS 등)을 정리한다(scope)."
        output_key: scope
  - id: 1
    name: 감사
    goal: 기준·시크릿 + 감사로그 병렬 점검
    max_concurrency: 2
    tasks:
      - task_id: c-cis
        persona: compliance-auditor
        name: 기준·시크릿
        instruction: "대상 자산의 CIS 기준 미준수 항목과 시크릿 노출을 증거와 함께 점검한다."
        output_key: cis
        depends_on: [c-scope]
      - task_id: c-audit
        persona: siem-log-analyst
        name: 감사로그 점검
        instruction: "로깅 활성화·보존·감사추적이 기준을 충족하는지(Wazuh 로그) 점검한다."
        output_key: audit_trail
        depends_on: [c-scope]
  - id: 2
    name: 보고
    goal: 미준수 통합 보고
    tasks:
      - task_id: c-report
        persona: soc-lead
        name: 보고서 통합
        instruction: "cis/audit_trail 미준수 항목을 심각도순으로 통합하고 개선 권고를 제시한다."
        output_key: report
        depends_on: [c-cis, c-audit]
```
