---
name: threat-hunt-team
description: "위협 헌팅 팀 하네스 — 범위설정→병렬 헌팅(헌터/로그/취약점)→룰화·보고. 트리거 - '위협 헌팅', 'threat hunt', '침해 흔적 탐색', '능동 탐색', '팀으로 헌팅'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 4
---

# threat-hunt-team

가설 기반 능동 위협 헌팅 팀. 리더(`soc-lead`)는 무발화 — 워커가 본문을 생산한다.

## workflow

```yaml
concurrency_cap: 4
phases:
  - id: 0
    name: 범위 설정
    goal: 헌팅 대상·기간·정상 기준선 정의
    tasks:
      - task_id: h-scope
        persona: soc-triage-analyst
        name: 헌팅 범위·기준선
        instruction: "헌팅 대상 자산/기간과 정상 기준선(베이스라인)을 정리한다."
        output_key: scope
  - id: 1
    name: 병렬 헌팅
    goal: 가설/로그/취약점 3각 병렬 탐색
    max_concurrency: 4
    tasks:
      - task_id: h-hunt
        persona: threat-hunter
        name: 가설 헌팅
        instruction: "범위 기반 가설로 IoC/TTP 를 능동 탐색·검증한다."
        output_key: hunt
        depends_on: [h-scope]
      - task_id: h-logs
        persona: siem-log-analyst
        name: 로그 상관
        instruction: "범위 기간 로그로 이상 상관·타임라인을 구성한다."
        output_key: timeline
        depends_on: [h-scope]
      - task_id: h-vuln
        persona: vuln-asset-manager
        name: 노출·취약점
        instruction: "범위 자산의 노출 서비스·CVE 를 식별·우선순위화한다."
        output_key: vuln
        depends_on: [h-scope]
  - id: 2
    name: 룰화·보고
    goal: 확인 위협 룰화 + 통합 보고
    max_concurrency: 2
    tasks:
      - task_id: h-detect
        persona: detection-engineer
        name: 탐지 룰화
        instruction: "헌팅에서 확인된 IoC 를 지속 탐지 룰로 만든다."
        output_key: detections
        depends_on: [h-hunt]
        verify:
          enabled: true
          criteria:
            - "각 룰에 근거 IoC/TTP 가 있는가"
            - "배포 후 동작이 확인되었는가"
          max_retries: 2
          verifier_persona: soc-lead
      - task_id: h-report
        persona: soc-lead
        name: 헌팅 보고
        instruction: "scope/hunt/timeline/vuln/detections 를 통합해 헌팅 보고서를 만든다."
        output_key: report
        depends_on: [h-hunt, h-logs, h-vuln, h-detect]
```
