---
name: incident-response-team
description: "SOC 인시던트 대응 팀 하네스 — 트리아지→조사(병렬)→봉쇄·탐지(검증)→보고. 트리거 - '인시던트 대응', '침해 대응', '알림 조사하고 차단', '격리 대응', 'incident response', '팀으로 대응'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 4
---

# incident-response-team

SOC 인시던트 대응 6단계 팀 오케스트레이션. 리더(`soc-lead`)는 무발화 — 워커가 모든 본문을 생산한다.
컨테이너는 자산으로, 페르소나가 기존 skill(`docker exec` 등)로 작용한다.

## workflow

```yaml
concurrency_cap: 4
phases:
  - id: 0
    name: 트리아지
    goal: 알림/요청 초기 분류·심각도 산정
    tasks:
      - task_id: t-triage
        persona: soc-triage-analyst
        name: 초기 트리아지
        instruction: "요청/알림을 분류하고 사건 후보·심각도·영향 표면을 산출한다(triage)."
        output_key: triage
  - id: 1
    name: 조사
    goal: 타임라인 + 위협 헌팅 병렬 조사
    max_concurrency: 3
    tasks:
      - task_id: t-timeline
        persona: siem-log-analyst
        name: 타임라인 구성
        instruction: "트리아지 사건 후보에 대해 SIEM(Wazuh)/IDS(Suricata) 로그로 시간순 타임라인·상관을 구성한다."
        output_key: timeline
        depends_on: [t-triage]
      - task_id: t-hunt
        persona: threat-hunter
        name: 위협 헌팅
        instruction: "트리아지 후보 기반 가설(C2/횡적이동 등)을 세워 IoC·TTP 를 수집·검증한다."
        output_key: hunt
        depends_on: [t-triage]
  - id: 2
    name: 봉쇄·탐지
    goal: 차단·격리 + 지속 탐지 룰
    max_concurrency: 3
    tasks:
      - task_id: t-contain
        persona: incident-responder
        name: 봉쇄·격리
        instruction: "확인된 위협을 최소 범위로 차단하고 증거를 보존하며 IoC 를 추출한다."
        output_key: containment
        depends_on: [t-hunt, t-timeline]
        verify:
          enabled: true
          criteria:
            - "차단 범위가 특정 IP/포트/프로세스로 한정되었는가"
            - "증거 보존 경로가 명시되었는가"
            - "변경이 실제 적용되어 확인되었는가"
          max_retries: 2
          verifier_persona: soc-lead
      - task_id: t-detect
        persona: detection-engineer
        name: 탐지 룰 배포
        instruction: "헌팅의 IoC/TTP 를 Suricata/Wazuh/ModSec 룰로 배포·검증한다."
        output_key: detections
        depends_on: [t-hunt]
        verify:
          enabled: true
          criteria:
            - "각 룰에 근거 IoC/TTP 가 있는가"
            - "배포 후 동작이 확인되었는가"
            - "오탐 위험이 평가되었는가"
          max_retries: 2
          verifier_persona: soc-lead
  - id: 3
    name: 보고
    goal: 통합 보고서
    tasks:
      - task_id: t-report
        persona: soc-lead
        name: 보고서 통합
        instruction: "triage/timeline/hunt/containment/detections 를 P0/P1/P2 우선순위로 통합 보고한다."
        output_key: report
        depends_on: [t-contain, t-detect]
```
