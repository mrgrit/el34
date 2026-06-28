---
name: ai-security-team
description: "AI/LLM 보안 점검 팀 하네스 — 범위→적대적 평가(인젝션/RAG)→(필요시)모델 격리(검증)→보고. 모델 자산 있을 때. 트리거 - 'AI 보안', 'LLM 보안', '프롬프트 인젝션', 'jailbreak 점검', 'RAG 무결성', 'ai security'."
allowed-tools: AgentTool, TaskCreate, SendMessage, Read, Write
concurrency_cap: 2
---

# ai-security-team

LLM 서비스의 프롬프트 인젝션·jailbreak·RAG 무결성을 평가하고, 위험 시 모델을 격리한다.
모델 자산(예: Ollama 컨테이너)이 존재할 때 의미가 있다.

## workflow

```yaml
concurrency_cap: 2
phases:
  - id: 0
    name: 범위
    goal: 모델 엔드포인트·표면 식별
    tasks:
      - task_id: a-scope
        persona: soc-triage-analyst
        name: 범위 산정
        instruction: "점검 대상 LLM 엔드포인트/모델/RAG 코퍼스 표면을 정리한다(scope)."
        output_key: scope
  - id: 1
    name: 적대적 평가
    goal: 인젝션/jailbreak/RAG 무결성 평가
    tasks:
      - task_id: a-assess
        persona: ai-security-analyst
        name: 적대적 평가
        instruction: "프롬프트 인젝션·jailbreak(garak/fuzz)와 RAG 코퍼스 무결성을 평가하고 성공 사례·심각도를 기록한다."
        output_key: assess
        depends_on: [a-scope]
  - id: 2
    name: 대응
    goal: 위험 모델 격리(필요 시)
    tasks:
      - task_id: a-contain
        persona: ai-security-analyst
        name: 모델 격리
        instruction: "평가에서 고위험이 확인된 모델/엔드포인트를 격리(model_isolate)하고 근거를 남긴다."
        output_key: containment
        depends_on: [a-assess]
        verify:
          enabled: true
          criteria:
            - "격리 대상이 고위험 근거와 함께 특정되었는가"
            - "격리가 실제 적용되어 확인되었는가"
            - "정상 서비스 영향 범위가 평가되었는가"
          max_retries: 2
          verifier_persona: soc-lead
  - id: 3
    name: 보고
    goal: 통합 보고
    tasks:
      - task_id: a-report
        persona: soc-lead
        name: 보고서 통합
        instruction: "assess/containment 를 위험 우선순위로 통합하고 모델 하드닝 권고를 제시한다."
        output_key: report
        depends_on: [a-contain]
```
