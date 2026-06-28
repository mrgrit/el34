---
name: vuln-assessment-team
description: "취약점·자산 평가 팀 하네스 — 범위→(취약점·컴플라이언스 병렬)→통합 보고. 읽기 전용. 트리거 - '취약점 평가', '취약점 점검', '노출 점검', '자산 점검', 'vuln assessment', 'vulnerability scan'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 3
---

# vuln-assessment-team

노출 서비스·CVE 식별과 기준 미준수 점검을 병렬로 수행해 위험 우선순위를 보고한다(읽기 전용).
리더(`soc-lead`)는 무발화로 통합만 한다.

## workflow

```yaml
concurrency_cap: 3
phases:
  - id: 0
    name: 범위
    goal: 평가 대상 자산·범위 산정
    tasks:
      - task_id: v-scope
        persona: soc-triage-analyst
        name: 범위 산정
        instruction: "평가 대상 자산/네트워크 범위와 우선순위를 정리한다(scope)."
        output_key: scope
  - id: 1
    name: 평가
    goal: 취약점 + 컴플라이언스 병렬 평가
    max_concurrency: 2
    tasks:
      - task_id: v-vuln
        persona: vuln-asset-manager
        name: 취약점·노출
        instruction: "범위 자산의 노출 서비스(포트/웹)와 CVE 를 식별하고 CVSS·악용가능성으로 우선순위화한다."
        output_key: vuln
        depends_on: [v-scope]
      - task_id: v-comp
        persona: compliance-auditor
        name: 기준·시크릿
        instruction: "범위 자산의 CIS 기준 미준수와 시크릿 노출을 점검한다."
        output_key: compliance
        depends_on: [v-scope]
  - id: 2
    name: 보고
    goal: 위험 우선순위 통합 보고
    tasks:
      - task_id: v-report
        persona: soc-lead
        name: 보고서 통합
        instruction: "vuln/compliance 를 위험도(영향×악용가능성) 우선순위로 통합하고 조치 권고를 제시한다."
        output_key: report
        depends_on: [v-vuln, v-comp]
```
