"""Bastion Harness Auto-Generator — 경험 + 인프라 기반 하네스 자동 생성 (Phase C).

수동 md(.bastion/agents,skills) 작성 없이, **발견된 인프라(discovery) + 누적 경험
(Experience Graph)** 로부터 하네스(HarnessSpec)를 합성한다. 책의 dependency-mapper 방식
(결정론 초안 → (옵션)매니저 LLM 정제 → 검증, 실패 시 결정론 폴백)을 따른다.

생성 신호
---------
- **페르소나 선택**: 기본 SOC 페르소나 라이브러리 중, 그 역할이 의미를 가지려면 존재해야 할
  자산(PERSONA_ASSET_REQ)이 discovery 결과에 있을 때만 포함. (예: ai-security-analyst 는
  모델 자산(ai-model)이 있을 때만 → el34 엔 없으므로 자동 제외; Ollama 컨테이너가 있으면 포함.)
- **모델 티어**: 페르소나 정의의 model_tier(reasoning/execution/attack).
- **Phase DAG**: SOC 라이프사이클 템플릿(트리아지→조사→봉쇄·탐지→(퍼플)→보고)을 선택된
  페르소나로 파라미터화. depends_on 은 존재하는 태스크만 참조.
- **verify 게이트**: 상태 변경(can_write) 페르소나의 태스크에 검증자(soc-lead) 게이트 부여.
- **경험 보강**: ExperienceLearner.get_context(요청) 의 학습된 주의/패턴을 전역 규칙·태스크
  지시에 주입. (옵션) lookup.decide 로 승격 playbook 을 태스크에 바인딩.

산출
----
- HarnessSpec(source="auto") + KG 영속화.
- 감사 아티팩트: harness/generated/<id>/{spec.json, 00_team_table.md, 01_phase_matrix.md,
  03_model_rationale.md, batches.json} (책 팀 문서 형식).
"""
from __future__ import annotations

import os
import json

from bastion.harness import (HarnessSpec, Persona, Phase, Task, Verify,
                             load_personas, validate_spec, topo_batches,
                             resolve_model, save_to_kg, resolve_harness_dir)

# 페르소나가 유용하려면 present 해야 하는 자산 역할(OR). 빈 리스트 = 항상 포함.
PERSONA_ASSET_REQ: dict[str, list[str]] = {
    "soc-lead": [],
    "soc-triage-analyst": [],
    "forensics-malware-analyst": [],
    "compliance-auditor": [],
    "threat-hunter": ["siem", "ids", "web"],
    "siem-log-analyst": ["siem"],
    "network-firewall-analyst": ["fw"],
    "vuln-asset-manager": ["attacker", "app", "web"],
    "detection-engineer": ["ids", "web", "siem"],
    "incident-responder": ["fw", "siem"],
    "ai-security-analyst": ["ai-model"],
    "red-team-operator": ["attacker"],
}

# 각 태스크 verify 기준 템플릿(상태 변경 태스크)
_VERIFY_CRITERIA = {
    "t-contain": ["차단 범위가 특정 IP/포트/프로세스로 한정", "증거 보존 경로 명시", "변경이 실제 적용되어 확인됨"],
    "t-detect": ["각 룰에 근거 IoC/TTP", "배포 후 동작 확인", "오탐 위험 평가"],
    "t-netpolicy": ["변경 전 현재 룰셋 스냅샷", "차단 범위 최소화", "변경 후 동작 verify"],
    "t-forensics": ["휘발성 순서 준수", "IoC 타입별 구조화", "증거 무결성 기록"],
    "t-redteam": ["통제 범위 준수", "각 공격에 탐지/차단 발현 여부", "우회/누락 인계"],
}


def _present_roles(agent, discovery_map: dict | None) -> dict[str, str]:
    """discovery 역할맵 확보(없으면 스캔 시도). {role: container}."""
    if discovery_map:
        return dict(discovery_map)
    try:
        from bastion.discovery import discovered_map, discover_infra
        m = discovered_map()
        if m:
            return m
        return discover_infra(getattr(agent, "vm_ips", {}), register_assets=False).get("role_map", {})
    except Exception:
        return {}


def generate_harness(request: str, agent, harness_id: str = "soc-auto",
                     discovery_map: dict | None = None,
                     bind_playbooks: bool = False,
                     emit_artifacts: bool = True) -> HarnessSpec:
    """발견 인프라 + 경험으로 SOC 하네스를 합성한다(결정론). 검증된 HarnessSpec 반환."""
    role_map = _present_roles(agent, discovery_map)
    present = set(role_map.keys())
    personas_all = load_personas()

    # ── 1) 페르소나 선택 (present 자산 매칭) ──────────────────────────────
    selected: dict[str, Persona] = {}
    for role, p in personas_all.items():
        req = PERSONA_ASSET_REQ.get(role, [])
        if (not req) or (set(req) & present):
            selected[role] = p
    # 필수 코어 보장
    for must in ("soc-lead", "soc-triage-analyst"):
        if must in personas_all:
            selected.setdefault(must, personas_all[must])

    # Phase D: 과거 성과/교훈 피드백 반영(모델 티어 조정 + 실패 교훈 주입)
    try:
        from bastion.feedback import apply_feedback
        for r in list(selected):
            selected[r] = apply_feedback(selected[r])
    except Exception:
        pass

    has = lambda r: r in selected  # noqa: E731

    # ── 2) SOC 라이프사이클 DAG (선택 페르소나로 파라미터화) ───────────────
    phases: list[Phase] = []

    # P0 트리아지
    p0 = Phase(id=0, name="트리아지", goal="알림/요청 초기 분류·심각도 산정")
    p0.tasks.append(Task(task_id="t-triage", persona="soc-triage-analyst",
                         name="초기 트리아지", output_key="triage",
                         instruction="요청/알림을 분류하고 사건 후보·심각도·영향 표면을 산출한다."))
    phases.append(p0)

    # P1 조사 (병렬)
    inv: list[str] = []
    p1 = Phase(id=1, name="조사", goal="병렬 조사(헌팅/로그/취약점)")
    if has("threat-hunter"):
        p1.tasks.append(Task(task_id="t-hunt", persona="threat-hunter", name="위협 헌팅",
                             output_key="hunt", depends_on=["t-triage"],
                             instruction="트리아지 후보 기반 가설로 IoC/TTP 를 능동 탐색·검증한다."))
        inv.append("t-hunt")
    if has("siem-log-analyst"):
        p1.tasks.append(Task(task_id="t-timeline", persona="siem-log-analyst", name="타임라인",
                             output_key="timeline", depends_on=["t-triage"],
                             instruction="SIEM/IDS 로그로 시간순 타임라인·상관을 구성한다."))
        inv.append("t-timeline")
    if has("vuln-asset-manager"):
        p1.tasks.append(Task(task_id="t-vuln", persona="vuln-asset-manager", name="취약점·노출",
                             output_key="vuln", depends_on=["t-triage"],
                             instruction="대상 자산의 노출 서비스·CVE 를 식별·우선순위화한다."))
        inv.append("t-vuln")
    if has("compliance-auditor"):
        p1.tasks.append(Task(task_id="t-compliance", persona="compliance-auditor", name="컴플라이언스",
                             output_key="compliance", depends_on=["t-triage"],
                             instruction="CIS/시크릿 기준 미준수 항목을 점검한다."))
        inv.append("t-compliance")
    if p1.tasks:
        phases.append(p1)
    inv_dep = inv or ["t-triage"]

    # P2 봉쇄·탐지 (verify)
    cont: list[str] = []
    p2 = Phase(id=2, name="봉쇄·탐지", goal="차단·격리 + 지속 탐지 룰")
    def _verify(tid):
        return Verify(enabled=True, criteria=_VERIFY_CRITERIA.get(tid, []),
                      max_retries=2, verifier_persona="soc-lead")
    if has("incident-responder"):
        p2.tasks.append(Task(task_id="t-contain", persona="incident-responder", name="봉쇄·격리",
                             output_key="containment", depends_on=list(inv_dep),
                             instruction="확인된 위협을 최소 범위로 차단하고 증거를 보존하며 IoC 를 추출한다.",
                             verify=_verify("t-contain")))
        cont.append("t-contain")
    if has("detection-engineer"):
        dep = ["t-hunt"] if "t-hunt" in inv else list(inv_dep)
        p2.tasks.append(Task(task_id="t-detect", persona="detection-engineer", name="탐지 룰",
                             output_key="detections", depends_on=dep,
                             instruction="IoC/TTP 를 Suricata/Wazuh/ModSec 룰로 배포·검증한다.",
                             verify=_verify("t-detect")))
        cont.append("t-detect")
    if has("network-firewall-analyst"):
        dep = ["t-contain"] if "t-contain" in cont else list(inv_dep)
        p2.tasks.append(Task(task_id="t-netpolicy", persona="network-firewall-analyst", name="네트워크 정책",
                             output_key="netpolicy", depends_on=dep,
                             instruction="노출면/방화벽 정책을 점검하고 차단/허용 룰을 최소 범위로 조정한다.",
                             verify=_verify("t-netpolicy")))
        cont.append("t-netpolicy")
    if has("forensics-malware-analyst"):
        p2.tasks.append(Task(task_id="t-forensics", persona="forensics-malware-analyst", name="포렌식",
                             output_key="forensics", depends_on=list(inv_dep),
                             instruction="대상 자산에서 증거를 보존·분석하고 IoC 를 추출한다.",
                             verify=_verify("t-forensics")))
        cont.append("t-forensics")
    if p2.tasks:
        phases.append(p2)

    # P3 퍼플 검증 (verify)
    if has("red-team-operator") and "t-detect" in cont:
        p3 = Phase(id=3, name="퍼플 검증", goal="탐지/차단 동작 검증")
        p3.tasks.append(Task(task_id="t-redteam", persona="red-team-operator", name="탐지 검증",
                             output_key="redteam", depends_on=["t-detect"],
                             instruction="배포된 탐지/차단이 작동하는지 통제된 공격으로 검증한다.",
                             verify=_verify("t-redteam")))
        phases.append(p3)

    # P4 보고 (soc-lead 통합)
    all_prior = [t.task_id for ph in phases for t in ph.tasks]
    p4 = Phase(id=4, name="보고", goal="통합 보고서")
    p4.tasks.append(Task(task_id="t-report", persona="soc-lead", name="보고서 통합",
                         output_key="report", depends_on=list(all_prior),
                         instruction="모든 산출물을 P0/P1/P2 우선순위로 통합 보고한다."))
    phases.append(p4)

    # Phase D: 저성과(force_verify) 페르소나 태스크에 verify 게이트 강제(검증자 soc-lead)
    for ph in phases:
        for t in ph.tasks:
            p = selected.get(t.persona)
            if (p and (p.meta or {}).get("force_verify")
                    and t.persona != "soc-lead"
                    and not (t.verify and t.verify.enabled)):
                t.verify = Verify(enabled=True,
                                  criteria=_VERIFY_CRITERIA.get(t.task_id, ["산출물이 검증 기준을 충족하는가"]),
                                  max_retries=2, verifier_persona="soc-lead")

    # ── 3) 경험 보강 (로컬, LLM 불필요) ──────────────────────────────────
    rules: list[str] = []
    try:
        from bastion.harness import parse_rules_md
        rules = parse_rules_md()
    except Exception:
        rules = []
    try:
        exp_ctx = agent.experience.get_context(request) if getattr(agent, "experience", None) else ""
        if exp_ctx:
            rules.append("학습된 주의(경험): " + exp_ctx.replace("\n", " ")[:600])
    except Exception:
        pass

    # (옵션) 승격 playbook 바인딩 — LLM 사용, 기본 off
    if bind_playbooks:
        try:
            from bastion.lookup import decide, build_lookup_prompt
            d = decide(request, agent.ollama_url, agent.model)
            if d.get("decision") in ("reuse", "adapt") and d.get("playbook_id"):
                inject = build_lookup_prompt(d)
                if inject:
                    p0.tasks[0].instruction += "\n\n[참고 플레이북]\n" + inject[:1200]
        except Exception:
            pass

    team = list(selected.values())
    spec = HarnessSpec(
        harness_id=harness_id, name=f"{harness_id} (auto)",
        description="discovery + Experience 기반 자동 생성 SOC 하네스",
        source="auto", rules=rules, concurrency_cap=4, team=team, phases=phases,
        triggers=[], meta={"present_roles": sorted(present), "request": request},
    )

    # Phase D (옵션): 매니저 LLM 정제 — instruction/criteria 개선(구조 불변, fallback).
    if os.getenv("BASTION_HARNESS_LLM_REFINE", "0") == "1":
        try:
            _llm_refine(spec, agent)
        except Exception:
            pass

    # ── 4) 검증 + 영속화 + 아티팩트 ──────────────────────────────────────
    errs = validate_spec(spec)
    spec.meta["validation_errors"] = errs
    try:
        save_to_kg(spec)
    except Exception:
        pass
    if emit_artifacts:
        try:
            _emit_artifacts(spec)
        except Exception:
            pass
    return spec


# ── (옵션) 매니저 LLM 정제 — 구조 불변, instruction/criteria 만 개선 ─────────
def _llm_refine(spec: HarnessSpec, agent) -> None:
    import httpx
    tasks = spec.all_tasks()
    brief = [{"task_id": t.task_id, "persona": t.persona, "name": t.name,
              "instruction": t.instruction,
              "criteria": (t.verify.criteria if (t.verify and t.verify.enabled) else [])}
             for t in tasks]
    sys = ("너는 SOC 하네스 설계자다. 아래 태스크들의 instruction 과 verify criteria 를 더 "
           "구체적·실행가능하게 다듬어라. 태스크 추가/삭제/구조 변경 금지. JSON 만 출력: "
           "{\"<task_id>\": {\"instruction\": \"...\", \"criteria\": [\"...\"]}}")
    user = (f"요청: {spec.meta.get('request','')}\n\n태스크:\n"
            f"{json.dumps(brief, ensure_ascii=False)}\n\nJSON:")
    model = resolve_model("reasoning") or getattr(agent, "model", "")
    r = httpx.post(f"{agent.ollama_url}/api/chat", json={
        "model": model,
        "messages": [{"role": "system", "content": sys},
                     {"role": "user", "content": user}],
        "stream": False, "options": {"temperature": 0.2, "num_predict": 1500}},
        timeout=120.0)
    text = ((r.json() or {}).get("message", {}) or {}).get("content", "") or ""
    s = text[text.find("{"): text.rfind("}") + 1] if "{" in text and "}" in text else ""
    data = json.loads(s) if s else {}
    by_id = {t.task_id: t for t in tasks}
    if isinstance(data, dict):
        for tid, upd in data.items():
            t = by_id.get(tid)
            if not t or not isinstance(upd, dict):
                continue
            if upd.get("instruction"):
                t.instruction = str(upd["instruction"])[:800]
            if (t.verify and t.verify.enabled and isinstance(upd.get("criteria"), list)
                    and upd["criteria"]):
                t.verify.criteria = [str(c)[:200] for c in upd["criteria"]][:5]
    spec.meta["llm_refined"] = True


# ── 감사 아티팩트 (책 팀 문서 형식) ─────────────────────────────────────────
def _emit_artifacts(spec: HarnessSpec) -> str:
    out_dir = os.path.join(resolve_harness_dir(), "generated", spec.harness_id)
    os.makedirs(out_dir, exist_ok=True)

    with open(os.path.join(out_dir, "spec.json"), "w", encoding="utf-8") as f:
        json.dump(spec.to_dict(), f, ensure_ascii=False, indent=2)

    # 00_team_table.md
    lines = ["# 팀 구성 (자동 생성)", "",
             "| role | model_tier | model | write | allowed_skills |",
             "|------|-----------|-------|-------|----------------|"]
    for p in spec.team:
        lines.append(f"| {p.role} | {p.model_tier} | {resolve_model(p.model_tier)} | "
                     f"{'✓' if p.can_write else '✗'} | {', '.join(p.allowed_skills)} |")
    lines += ["", f"present 자산 역할: {spec.meta.get('present_roles')}"]
    with open(os.path.join(out_dir, "00_team_table.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    # 01_phase_matrix.md
    roles = [p.role for p in spec.team]
    ph_ids = [ph.id for ph in spec.phases]
    pm = ["# Phase × 페르소나 활성 매트릭스 (자동 생성)", "",
          "| 페르소나 \\ Phase | " + " | ".join(str(i) for i in ph_ids) + " |",
          "|" + "---|" * (len(ph_ids) + 1)]
    role_phase = {r: set() for r in roles}
    for ph in spec.phases:
        for t in ph.tasks:
            role_phase.setdefault(t.persona, set()).add(ph.id)
    for r in roles:
        pm.append(f"| {r} | " + " | ".join("O" if i in role_phase.get(r, set()) else "." for i in ph_ids) + " |")
    pm += ["", f"동시 활성 상한(concurrency_cap): {spec.concurrency_cap}"]
    with open(os.path.join(out_dir, "01_phase_matrix.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(pm))

    # 03_model_rationale.md
    mr = ["# 모델 배정 근거 (자동 생성)", "",
          "- reasoning(설계/판정/교차추론) → LLM_MANAGER_MODEL",
          "- execution(확정 명세 단일 실행) → LLM_SUBAGENT_MODEL",
          "- attack(적대 모의) → LLM_MANAGER_MODEL_UNSAFE", ""]
    for p in spec.team:
        mr.append(f"- `{p.role}`: {p.model_tier} → {resolve_model(p.model_tier)}")
    with open(os.path.join(out_dir, "03_model_rationale.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(mr))

    # batches.json (위상정렬 — 책 batches 대응)
    try:
        batches = topo_batches(spec.all_tasks())
        bj = [{"batch": i, "tasks": [{"task_id": t.task_id, "persona": t.persona,
                                       "depends_on": t.depends_on,
                                       "verify": bool(t.verify and t.verify.enabled)}
                                      for t in b]}
              for i, b in enumerate(batches)]
    except Exception:
        bj = []
    with open(os.path.join(out_dir, "batches.json"), "w", encoding="utf-8") as f:
        json.dump(bj, f, ensure_ascii=False, indent=2)

    return out_dir
