---
name: forensics-investigation-team
description: "포렌식·침해 분석 팀 하네스 — 범위→(증거 수집(검증)·타임라인 병렬)→분석·IoC(검증)→보고. 트리거 - '포렌식', '침해 분석', '증거 수집', '메모리 분석', 'forensics', 'incident analysis'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 2
---

# forensics-investigation-team

의심 자산에서 증거를 보존·분석하고 IoC 를 추출한다. 수집/덤프는 쓰기·승인 대상이며 휘발성 순서를 지킨다.

## workflow

```yaml
concurrency_cap: 2
phases:
  - id: 0
    name: 범위
    goal: 조사 대상 자산·가설 산정
    tasks:
      - task_id: f-scope
        persona: soc-triage-analyst
        name: 범위 산정
        instruction: "조사 대상 자산과 침해 가설, 보존 대상을 정리한다(scope)."
        output_key: scope
  - id: 1
    name: 수집
    goal: 증거 수집 + 타임라인 병렬
    max_concurrency: 2
    tasks:
      - task_id: f-collect
        persona: forensics-malware-analyst
        name: 증거 수집
        instruction: "휘발성 순서에 따라 대상 자산의 증거를 수집·보존(forensic_collect/memory_dump)하고 무결성을 기록한다."
        output_key: evidence
        depends_on: [f-scope]
        verify:
          enabled: true
          criteria:
            - "휘발성 순서(메모리→디스크)가 지켜졌는가"
            - "증거 무결성(해시/경로)이 기록되었는가"
            - "수집 범위가 대상 자산으로 한정되었는가"
          max_retries: 2
          verifier_persona: soc-lead
      - task_id: f-timeline
        persona: siem-log-analyst
        name: 타임라인
        instruction: "대상 자산 관련 로그로 사건 시간순 타임라인을 구성한다."
        output_key: timeline
        depends_on: [f-scope]
  - id: 2
    name: 분석
    goal: 증거 분석 + IoC 추출
    tasks:
      - task_id: f-analyze
        persona: forensics-malware-analyst
        name: 분석·IoC
        instruction: "수집 증거와 타임라인을 분석해 근본원인·악성 아티팩트를 규명하고 IoC 를 구조화 추출(ioc_export)한다."
        output_key: analysis
        depends_on: [f-collect, f-timeline]
        verify:
          enabled: true
          criteria:
            - "IoC 가 타입별로 구조화되었는가"
            - "근본원인/감염경로가 증거로 뒷받침되는가"
            - "타임라인과 모순이 없는가"
          max_retries: 2
          verifier_persona: soc-lead
  - id: 3
    name: 보고
    goal: 통합 보고
    tasks:
      - task_id: f-report
        persona: soc-lead
        name: 보고서 통합
        instruction: "evidence/timeline/analysis 를 사건 서술 + IoC + 권고로 통합 보고한다."
        output_key: report
        depends_on: [f-analyze]
```
