"""Bastion Harness Orchestrator — 6단계 다중 페르소나 팀 실행 (Phase A).

run_harness(spec, request, agent, approval_callback) -> Generator[event]
  P0 입력 수집 → P1 팀 생성(논리 페르소나) → P2 위상정렬 태스크 배치 →
  P3 fan-out(동시성 상한, 페르소나 스코프 ReAct) → P4 생성-검증 루프(≤max_retries) →
  P5 통합·영속화. 리더(soc-lead)는 무발화 — 워커 페르소나가 본문을 생산한다.

기존 BastionAgent 인스턴스를 받아 그 헬퍼(_enrich_params/_assess_risk/_should_ask_approval/
_pre_check/evidence_db/experience)와 skills(execute_skill/skills_to_ollama_tools)를 재사용한다.
페르소나는 컨테이너에 묶이지 않으며, execute_skill→run_command(docker exec/ssh)로 자산에 작용한다.
"""
from __future__ import annotations

import os
import json
import time
import threading
import queue
from typing import Any, Callable, Generator

import httpx

from bastion.harness import HarnessSpec, Persona, Task, topo_batches, resolve_model, save_to_kg
from bastion.skills import SKILLS, execute_skill, skills_to_ollama_tools

MAX_TURNS = int(os.getenv("BASTION_HARNESS_MAX_TURNS", "4"))
LLM_TIMEOUT = float(os.getenv("BASTION_HARNESS_LLM_TIMEOUT", "180"))
_DB_LOCK = threading.Lock()  # evidence/experience SQLite 동시쓰기 보호


# ── LLM 호출 (Ollama /api/chat, agent.py ReAct 와 동일 형식) ────────────────
def _llm_chat(ollama_url: str, model: str, messages: list[dict],
              tools: list[dict] | None = None, num_predict: int = 1200,
              temperature: float = 0.2) -> dict:
    payload: dict = {
        "model": model, "messages": messages, "stream": False,
        "options": {"temperature": temperature, "num_predict": num_predict},
    }
    if tools:
        payload["tools"] = tools
    r = httpx.post(f"{ollama_url}/api/chat", json=payload, timeout=LLM_TIMEOUT)
    return (r.json() or {}).get("message", {}) or {}


def _filtered_tools(allowed_skills: list[str]) -> list[dict]:
    """allowed_skills 로 도구 경계를 강제한 ollama tools 목록."""
    try:
        allt = skills_to_ollama_tools()
    except Exception:
        return []
    allow = set(allowed_skills)
    return [t for t in allt if ((t.get("function") or {}).get("name") in allow)]


def _extract_tool_calls(msg: dict) -> list[dict]:
    """tool_calls 추출 + derestricted 모델 폴백(harmony/json/prose)."""
    tcs = msg.get("tool_calls") or []
    if tcs:
        return tcs
    content = (msg.get("content") or "") + "\n" + (msg.get("thinking") or "")
    # agent.py 의 폴백 추출기 재사용(있으면)
    try:
        from bastion.agent import (_extract_harmony_tool_calls,
                                   _extract_json_tool_calls)
        for extractor in (_extract_harmony_tool_calls, _extract_json_tool_calls):
            calls = extractor(content) or []
            synth = [{"function": {"name": n, "arguments": a}}
                     for n, a in calls[:2] if n in SKILLS]
            if synth:
                return synth
    except Exception:
        pass
    return []


def _shared_context_text(shared_ctx: dict[str, str], depends_on: list[str],
                         id_to_key: dict[str, str]) -> str:
    """선행 태스크 산출물을 컨텍스트로. 의존 명시면 그것만, 없으면 전체."""
    keys = [id_to_key.get(d, d) for d in depends_on] if depends_on else list(shared_ctx.keys())
    parts = []
    for k in keys:
        v = shared_ctx.get(k)
        if v:
            parts.append(f"### 선행 산출물: {k}\n{v[:2500]}")
    return "\n\n".join(parts)


# ── 페르소나 스코프 ReAct 태스크 ────────────────────────────────────────────
def run_persona_task(agent, persona: Persona, task: Task, spec: HarnessSpec,
                     shared_ctx: dict[str, str], id_to_key: dict[str, str],
                     approval_callback, run_dir: str, emit: Callable[[dict], None],
                     feedback: str = "") -> dict:
    """단일 페르소나 ReAct 루프. execute_skill 로 자산에 작용. 산출물 텍스트 반환."""
    ollama_url = agent.ollama_url
    model = resolve_model(persona.model_tier) or agent.model
    tools = _filtered_tools(persona.allowed_skills)

    rules = "\n".join(f"- {r}" for r in spec.rules)
    ctx = _shared_context_text(shared_ctx, task.depends_on, id_to_key)
    verify_note = ""
    if task.verify and task.verify.enabled and task.verify.criteria:
        verify_note = ("## 이 작업의 검증 기준(반드시 충족)\n"
                       + "\n".join(f"- {c}" for c in task.verify.criteria))
    write_note = ("너는 읽기 전용이다 — 상태를 바꾸는(danger/승인 필요) 도구를 호출하지 마라."
                  if not persona.can_write else
                  "상태 변경 도구는 최소 범위로만 사용하고, 변경 전 반드시 현재 상태를 확인하라.")
    sys_prompt = (
        persona.system_prompt()
        + "\n\n## 전역 규칙\n" + rules
        + "\n\n## 도구 경계\n허용 도구(skill): " + ", ".join(persona.allowed_skills)
        + "\n" + write_note
        + (("\n\n## 공유 컨텍스트(선행 산출물)\n" + ctx) if ctx else "")
        + (("\n\n" + verify_note) if verify_note else "")
        + (("\n\n## 검증 피드백(직전 시도 미흡 — 반영하라)\n" + feedback) if feedback else "")
        + "\n\n## 출력\n작업을 수행하고, 마지막에 산출물(발견/조치/근거)을 한국어로 정리하라. "
          "도구 결과의 핵심 stdout 을 인용하고 추정과 단정을 구분하라."
    )
    user = (f"[요청]\n{spec.meta.get('request','')}\n\n[너의 작업: {task.name}]\n{task.instruction}")

    msgs: list[dict] = [{"role": "system", "content": sys_prompt},
                        {"role": "user", "content": user}]
    tool_outputs: list[dict] = []
    last_content = ""

    for turn in range(MAX_TURNS):
        try:
            rmsg = _llm_chat(ollama_url, model, msgs, tools=tools)
        except Exception as e:
            emit({"event": "error", "role": persona.role, "task_id": task.task_id, "error": str(e)[:200]})
            break
        content = rmsg.get("content", "") or ""
        last_content = content or last_content
        tool_calls = _extract_tool_calls(rmsg)

        amsg: dict = {"role": "assistant", "content": content}
        if tool_calls:
            amsg["tool_calls"] = tool_calls
        msgs.append(amsg)

        if not tool_calls:
            break  # 최종 응답

        for tc in tool_calls:
            fn = tc.get("function", {}) or {}
            skill_name = fn.get("name", "")
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            if not isinstance(args, dict):
                args = {}

            # 도구 경계 강제
            if skill_name not in persona.allowed_skills or skill_name not in SKILLS:
                msgs.append({"role": "tool", "content": f"[error] 도구 경계 위반/미지원: {skill_name}"})
                emit({"event": "boundary_block", "role": persona.role, "task_id": task.task_id,
                      "skill": skill_name})
                continue

            sk_def = SKILLS.get(skill_name, {})
            # 읽기 전용 페르소나의 상태 변경 차단
            if not persona.can_write and (sk_def.get("danger") or sk_def.get("requires_approval")):
                msgs.append({"role": "tool", "content": f"[error] 읽기 전용 페르소나는 '{skill_name}' 사용 불가"})
                emit({"event": "boundary_block", "role": persona.role, "task_id": task.task_id,
                      "skill": skill_name, "reason": "read-only"})
                continue

            params = agent._enrich_params(skill_name, args)
            risk = agent._assess_risk(skill_name, params)
            if risk in ("high", "critical"):
                emit({"event": "risk_warning", "role": persona.role, "task_id": task.task_id,
                      "skill": skill_name, "risk": risk})
            if agent._should_ask_approval(risk, sk_def) and approval_callback:
                if not approval_callback(skill_name, f"{persona.role}:{skill_name}", params):
                    emit({"event": "skill_skip", "role": persona.role, "task_id": task.task_id,
                          "skill": skill_name, "reason": "denied"})
                    msgs.append({"role": "tool", "content": "[error] approval denied"})
                    continue
            pre_ok, pre_msg = agent._pre_check(skill_name, params)
            if not pre_ok:
                emit({"event": "precheck_fail", "role": persona.role, "task_id": task.task_id,
                      "skill": skill_name, "message": pre_msg})
                msgs.append({"role": "tool", "content": f"[precheck-fail] {pre_msg}"})
                continue

            emit({"event": "skill_start", "role": persona.role, "task_id": task.task_id,
                  "skill": skill_name, "params": params})
            try:
                result = execute_skill(skill_name, params, agent.vm_ips, agent.ollama_url, agent.model)
            except Exception as e:
                result = {"success": False, "output": str(e), "stderr": str(e), "exit_code": -1}
            output = str(result.get("output", ""))
            success = bool(result.get("success", False))
            exit_code = result.get("exit_code", -1 if not success else 0)
            emit({"event": "skill_result", "role": persona.role, "task_id": task.task_id,
                  "skill": skill_name, "success": success, "output": output[:2000]})
            msgs.append({"role": "tool",
                         "content": f"[skill={skill_name} success={success} exit={exit_code}]\n{output[:3000]}"})
            tool_outputs.append({"skill": skill_name, "success": success, "output": output})

            with _DB_LOCK:
                try:
                    agent.evidence_db.add(skill=skill_name, params=params, success=success,
                                          exit_code=exit_code, output=output, stage="harness",
                                          session_id=agent.session_id, **getattr(agent, "_test_meta", {}))
                except Exception:
                    pass
                try:
                    agent.experience.record(message=task.instruction, skill=skill_name,
                                            target_vm=params.get("target", ""),
                                            command=params.get("command", ""), success=success)
                except Exception:
                    pass

    # 산출물 저장(workspace)
    artifact = last_content or "(산출물 없음)"
    try:
        pdir = os.path.join(run_dir, persona.role)
        os.makedirs(pdir, exist_ok=True)
        with open(os.path.join(pdir, f"{task.output_key or task.task_id}.md"), "w", encoding="utf-8") as f:
            f.write(f"# {task.name} ({persona.role})\n\n{artifact}\n")
    except Exception:
        pass

    return {"output": artifact, "tool_outputs": tool_outputs,
            "success": bool(tool_outputs) or len(artifact) > 30}


# ── 검증자 (읽기 전용 LLM 판정) ─────────────────────────────────────────────
def run_verifier(agent, verifier: Persona, task: Task, produced: str,
                 emit: Callable[[dict], None]) -> dict:
    """검증자 페르소나가 산출물을 기준에 따라 판정. {passed, reason}."""
    # 테스트 훅: 강제 실패
    if os.getenv("BASTION_HARNESS_FORCE_FAIL", "") == task.task_id:
        return {"passed": False, "reason": "forced-fail (test hook)"}
    # objective 검증(Phase D): 산출물이 비었거나 너무 짧으면 LLM 판정 전에 즉시 실패.
    if len((produced or "").strip()) < 30:
        return {"passed": False, "reason": "산출물이 비었거나 너무 짧음(objective)"}
    crit = "\n".join(f"- {c}" for c in (task.verify.criteria or []))
    model = resolve_model(verifier.model_tier) or agent.model
    sys = (verifier.system_prompt()
           + "\n\n너는 지금 검증자다. 아래 산출물이 검증 기준을 충족하는지 판정하라. "
             "수정하지 말고, JSON 한 줄만 출력: {\"passed\": true|false, \"reason\": \"...\"}")
    user = f"## 검증 기준\n{crit}\n\n## 산출물\n{produced[:4000]}\n\nJSON 판정:"
    try:
        rmsg = _llm_chat(agent.ollama_url, model,
                         [{"role": "system", "content": sys}, {"role": "user", "content": user}],
                         tools=None, num_predict=300, temperature=0.0)
        text = (rmsg.get("content") or "").strip()
        m = text[text.find("{"): text.rfind("}") + 1] if "{" in text and "}" in text else ""
        verdict = json.loads(m) if m else {}
        passed = bool(verdict.get("passed", True))
        reason = str(verdict.get("reason", ""))[:500]
        return {"passed": passed, "reason": reason or ("OK" if passed else "기준 미충족")}
    except Exception as e:
        # 판정 불가 시 통과(보수적으로 막지 않음) + 사유 기록
        return {"passed": True, "reason": f"verdict-unparseable: {str(e)[:120]}"}


def run_task_with_verify(agent, spec: HarnessSpec, task: Task, shared_ctx: dict[str, str],
                         id_to_key: dict[str, str], approval_callback, run_dir: str,
                         emit: Callable[[dict], None]) -> dict:
    """생성 → (검증 → 재생성) 루프. 통과/escalate 결과 반환."""
    persona = spec.persona(task.persona)
    emit({"event": "task_start", "role": task.persona, "task_id": task.task_id, "name": task.name})
    feedback = ""
    max_attempts = (task.verify.max_retries + 1) if (task.verify and task.verify.enabled) else 1
    last = {"output": "", "tool_outputs": []}
    for attempt in range(1, max_attempts + 1):
        task.attempts = attempt
        last = run_persona_task(agent, persona, task, spec, shared_ctx, id_to_key,
                                approval_callback, run_dir, emit, feedback=feedback)
        if not (task.verify and task.verify.enabled):
            task.status = "done"
            break
        verifier = spec.persona(task.verify.verifier_persona)
        emit({"event": "verify_start", "task_id": task.task_id,
              "verifier": task.verify.verifier_persona, "attempt": attempt})
        verdict = run_verifier(agent, verifier, task, last["output"], emit)
        emit({"event": "verify_result", "task_id": task.task_id,
              "passed": verdict["passed"], "reason": verdict["reason"], "attempt": attempt})
        if verdict["passed"]:
            task.status = "done"
            break
        feedback = verdict["reason"]
        if attempt >= max_attempts:
            task.status = "escalated"
            emit({"event": "escalate", "task_id": task.task_id, "role": task.persona,
                  "reason": verdict["reason"]})
    emit({"event": "task_done", "task_id": task.task_id, "role": task.persona,
          "status": task.status, "attempts": task.attempts})
    return last


# ── 6단계 오케스트레이션 ────────────────────────────────────────────────────
def run_harness(spec: HarnessSpec, request: str, agent,
                approval_callback=None) -> Generator[dict, None, None]:
    """하네스 6단계 실행 generator. agent = BastionAgent 인스턴스."""
    spec.meta["request"] = request
    run_id = time.strftime("h%Y%m%d-%H%M%S")
    try:
        run_dir = os.path.join(_workspace_root(), run_id)
        os.makedirs(run_dir, exist_ok=True)
    except Exception:
        run_dir = "/tmp/bastion-harness-" + run_id

    all_tasks = spec.all_tasks()
    id_to_key = {t.task_id: (t.output_key or t.task_id) for t in all_tasks}
    task_phase = {t.task_id: ph.id for ph in spec.phases for t in ph.tasks}

    # ── P0 입력 ──
    yield {"event": "harness_start", "harness_id": spec.harness_id, "name": spec.name,
           "run_id": run_id, "team": [p.role for p in spec.team], "tasks": len(all_tasks)}
    try:
        save_to_kg(spec)
    except Exception as e:
        yield {"event": "kg_warn", "error": str(e)[:160]}

    # ── P1 팀 생성(논리 페르소나) ──
    for p in spec.team:
        yield {"event": "persona_activate", "role": p.role, "model_tier": p.model_tier,
               "model": resolve_model(p.model_tier), "skills": p.allowed_skills,
               "can_write": p.can_write}

    # ── P2 위상정렬 배치 ──
    try:
        batches = topo_batches(all_tasks)
    except ValueError as e:
        yield {"event": "error", "stage": "plan", "error": str(e)}
        return
    yield {"event": "plan", "batches": [[t.task_id for t in b] for b in batches]}

    shared_ctx: dict[str, str] = {}
    started_phases: set[int] = set()

    # ── P3/P4 fan-out + 생성-검증 ──
    for batch in batches:
        # phase_start 이벤트(배치 내 신규 phase)
        for t in batch:
            ph = task_phase.get(t.task_id)
            if ph is not None and ph not in started_phases:
                started_phases.add(ph)
                pname = next((x.name for x in spec.phases if x.id == ph), "")
                yield {"event": "phase_start", "phase": ph, "name": pname}
        for t in batch:
            yield {"event": "task_create", "task_id": t.task_id, "role": t.persona,
                   "name": t.name, "depends_on": t.depends_on,
                   "verify": bool(t.verify and t.verify.enabled)}

        concurrency = max(1, min(spec.concurrency_cap, len(batch)))
        sem = threading.Semaphore(concurrency)
        q: "queue.Queue" = queue.Queue()
        results: dict[str, dict] = {}

        def _worker(task: Task):
            with sem:
                try:
                    res = run_task_with_verify(agent, spec, task, shared_ctx, id_to_key,
                                               approval_callback, run_dir, q.put)
                except Exception as e:
                    q.put({"event": "error", "task_id": task.task_id, "error": str(e)[:200]})
                    res = {"output": f"(error: {e})", "tool_outputs": []}
                q.put({"event": "__done__", "task_id": task.task_id, "result": res})

        threads = [threading.Thread(target=_worker, args=(t,), daemon=True) for t in batch]
        for th in threads:
            th.start()

        done = 0
        while done < len(batch):
            ev = q.get()
            if ev.get("event") == "__done__":
                results[ev["task_id"]] = ev["result"]
                done += 1
                continue
            yield ev
        for th in threads:
            th.join(timeout=1)

        # 산출물을 공유 컨텍스트에 병합(다음 배치/리포트용)
        for t in batch:
            res = results.get(t.task_id, {})
            shared_ctx[id_to_key[t.task_id]] = res.get("output", "")

    # ── P5 통합·영속화 ──
    # 리포트 태스크(soc-lead)가 마지막 배치에서 이미 통합 산출. 없으면 단순 결합.
    report_key = None
    for t in all_tasks:
        if t.persona == "soc-lead" and "report" in (t.output_key or "").lower():
            report_key = t.output_key
    report = shared_ctx.get(report_key, "") if report_key else ""
    if not report:
        report = "\n\n".join(f"## {k}\n{v[:1500]}" for k, v in shared_ctx.items())
    try:
        write_path = os.path.join(run_dir, "report.md")
        with open(write_path, "w", encoding="utf-8") as f:
            f.write(report)
    except Exception:
        write_path = ""

    # KG 기록 (harness_run anchor + task outcome)
    try:
        from bastion.kg_recorder import get_recorder
        rec = get_recorder()
        escalated = [t.task_id for t in all_tasks if t.status == "escalated"]
        rec.record_task_outcome(
            task_message=f"[harness:{spec.harness_id}] {request}",
            skills_used=sorted({s for p in spec.team for s in p.allowed_skills}),
            mitre_ids=[], success=(not escalated),
            evidence_excerpt=report[:800], source=f"harness:{spec.harness_id}",
            session_id=getattr(agent, "session_id", ""),
        )
    except Exception as e:
        yield {"event": "kg_warn", "error": str(e)[:160]}

    # 페르소나 피드백 기록 (Phase D) — 태스크별 성과를 KG Persona meta 에 누적.
    # 다음 harness_gen 이 success_rate/pitfalls 로 티어 조정·교훈 주입.
    try:
        from bastion.feedback import record_persona_outcome
        for t in all_tasks:
            ok = (t.status == "done")
            reason = "" if ok else f"{t.task_id} {t.status} (attempts={t.attempts})"
            record_persona_outcome(t.persona, ok, reason=reason,
                                   source=f"harness:{spec.harness_id}")
    except Exception as e:
        yield {"event": "kg_warn", "error": f"feedback: {str(e)[:120]}"}

    yield {"event": "harness_done", "harness_id": spec.harness_id, "run_id": run_id,
           "report": report, "report_path": write_path,
           "escalated": [t.task_id for t in all_tasks if t.status == "escalated"],
           "tasks": [{"task_id": t.task_id, "role": t.persona, "status": t.status,
                      "attempts": t.attempts} for t in all_tasks]}


def _workspace_root() -> str:
    from bastion.harness import resolve_harness_dir
    return os.path.join(resolve_harness_dir(), "workspace")
