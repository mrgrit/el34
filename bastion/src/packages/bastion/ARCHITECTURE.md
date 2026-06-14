# Bastion 처리 프로세스

사용자 요청이 들어온 순간부터 실행·기록까지의 전체 흐름.

## 처리 흐름

```
사용자 입력
    │
    ▼
[main.py] console.input()
    ├─ sanitize_text()          — 제어문자 제거, 인코딩 정규화
    └─ agent.chat(user_input)
            │
            ▼
════════════════════════════════════════
 STAGE 1: PLANNING
════════════════════════════════════════
    │
    ├─ ① Playbook 매칭  (_select_playbook)
    │       LLM에 등록된 Playbook ID 중 하나를 반환하도록 요청
    │       → 매칭됨: EXECUTING (Playbook 경로)
    │
    ├─ ② Skill 선택  (_select_skills_multi)      ← Playbook 없을 때
    │       tool_calls 배열 우선, 실패 시 JSON 배열 fallback (format:"json")
    │       → [(skill_name, params), ...] 리스트
    │       → plan_preview 이벤트 발행 후 EXECUTING (Multi-skill 경로)
    │
    ├─ ③ Dynamic Playbook 생성  (_generate_dynamic_playbook)  ← Skill도 없을 때
    │       LLM이 JSON 스텝 배열을 직접 생성 (format:"json", temperature:0.0)
    │       → EXECUTING (Dynamic 경로)
    │
    └─ ④ Q&A 직접 답변                           ← 위 3개 모두 실패
            LLM 스트리밍 응답
            stream_start / stream_token / stream_end 이벤트

════════════════════════════════════════
 STAGE 2: EXECUTING
════════════════════════════════════════
    │
    ├─ [Playbook 경로]  run_playbook()
    │       step별: step_start
    │               → (requires_approval이면) approval_callback — 사용자 Y/n
    │               → execute_skill()
    │               → step_done
    │       완료: playbook_done 이벤트
    │
    ├─ [Multi-skill 경로]
    │       plan_preview 이벤트
    │         └─ main.py가 Rich 테이블로 전체 계획 출력 (dry-run 미리보기)
    │       skill별:
    │         _pre_check()          — health_check로 대상 VM 생존 확인
    │         _assess_risk()        — high이면 approval_callback (사용자 Y/n)
    │         execute_skill()
    │           └─ run_command(ip, script)
    │                └─ SubAgent A2A: POST http://{ip}:8002/a2a/run_script
    │         skill_result 이벤트
    │         _update_assets_from_result()  — assets 테이블 갱신
    │
    └─ [Dynamic 경로]  _run_dynamic_steps()
            동일: pre_check → risk 평가 → execute → result 이벤트

════════════════════════════════════════
 STAGE 3: VALIDATING
════════════════════════════════════════
    │
    └─ _stream_analysis_events()
            실행 결과를 LLM에 전달 → 분석 텍스트 스트리밍
            stream_start("분석") / stream_token / stream_end
            → evidence_db.save()  — SQLite에 기록

    ▼
[main.py] 이벤트 수신 → Rich 콘솔 출력
```

---

## 4단계 Fallback

| 우선순위 | 조건 | 처리 |
|---|---|---|
| 1 | 정적 Playbook 매칭 | YAML 정의 순서대로 실행 |
| 2 | Skill 하나 이상 선택됨 | Multi-skill 순차 실행 |
| 3 | 매칭 없음 | LLM이 동적으로 스텝 생성 |
| 4 | 보안 질문·설명 요청 | LLM 직접 답변 (Skill 미실행) |

---

## 데이터 흐름

```
사용자 입력
  → history  (최근 12턴 유지, 초과 시 LLM이 오래된 6턴 요약 압축)
  → RAG 인덱스  (관련 지식 컨텍스트 검색)
  → build_planning_prompt() / build_system_prompt()
  → Ollama /api/chat 또는 /api/generate

결과
  → EvidenceDB (SQLite: ~/.bastion/evidence.db)
      ├─ evidence 테이블: timestamp, skill, params, output, success, analysis
      └─ assets  테이블: role, ip, status, last_seen, notes
```

---

## 주요 컴포넌트

| 파일 | 역할 |
|---|---|
| `main.py` | TUI 루프, 이벤트 렌더링, 내장 명령어 처리 |
| `agent.py` | 전체 오케스트레이션, LLM 호출, history 관리 |
| `skills.py` | Skill 정의 (`SKILLS`), `execute_skill()`, `preview_skill()` |
| `playbook.py` | Playbook YAML 로드, `run_playbook()` |
| `prompt.py` | `build_planning_prompt()` / `build_system_prompt()` |
| `rag.py` | 지식 인덱스 구축·검색 |

---

## SubAgent A2A 프로토콜

Manager VM의 Bastion → 각 VM의 SubAgent HTTP 서버

```
POST http://{vm_ip}:8002/a2a/run_script
Body: {"script": "...bash script..."}
Response: {"stdout": "...", "stderr": "...", "returncode": 0}
```

각 VM에 SubAgent가 상주하며 Manager의 명령을 수신·실행.

---

## TUI 내장 명령어

| 명령어 | 설명 |
|---|---|
| `/skills` | 등록된 Skill 목록 |
| `/playbooks` | 등록된 Playbook 목록 |
| `/evidence` | 최근 실행 기록 10건 |
| `/search <키워드>` | Evidence 검색 |
| `/assets` | Asset 레지스트리 (VM 상태 추적) |
| `/stats` | Evidence·RAG 통계 |
| `/clear` | 대화 기록 초기화 |
| `/quit` | 종료 |
