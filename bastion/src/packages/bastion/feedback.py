"""Bastion Harness Feedback Loop — 실행 결과 기반 페르소나 자기개선 (Phase D).

하네스 실행 결과를 KG 의 Persona 노드에 누적(runs/successes/success_rate/pitfalls)하고,
다음 자동 생성(harness_gen) 시 그 피드백을 페르소나에 반영한다:
  - 과거 실패 교훈(pitfalls)을 페르소나 프롬프트(품질 자체 검증)에 주입.
  - success_rate 기반 모델 티어 조정: 검증된 읽기전용 페르소나는 경량화(reasoning→execution),
    저성과 페르소나는 상향(execution→reasoning)하고 harness_gen 이 verify 를 강화.

KG 기반(graph.Persona meta)이라 별도 저장소 없이 영속·재사용된다.
"""
from __future__ import annotations

import os
import json

# 티어 조정 정책 임계 (환경변수 override)
PROMOTE_RUNS = int(os.getenv("BASTION_FEEDBACK_PROMOTE_RUNS", "5"))
PROMOTE_RATE = float(os.getenv("BASTION_FEEDBACK_PROMOTE_RATE", "0.85"))
DEMOTE_RUNS = int(os.getenv("BASTION_FEEDBACK_DEMOTE_RUNS", "3"))
DEMOTE_RATE = float(os.getenv("BASTION_FEEDBACK_DEMOTE_RATE", "0.5"))
MAX_PITFALLS = 5


def _graph():
    from bastion.graph import get_graph
    return get_graph()


def _as_dict(v) -> dict:
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v:
        try:
            return json.loads(v)
        except Exception:
            return {}
    return {}


def record_persona_outcome(role: str, success: bool, reason: str = "",
                           source: str = "harness") -> dict:
    """Persona 노드 meta 에 성과 누적 + 실패 사유 pitfall 축적. 갱신된 meta 반환."""
    try:
        g = _graph()
        pid = f"persona:{role}"
        node = g.get_node(pid)
        content = _as_dict(node.get("content")) if node else {}
        meta = _as_dict(node.get("meta")) if node else {}
        runs = int(meta.get("runs", 0)) + 1
        successes = int(meta.get("successes", 0)) + (1 if success else 0)
        meta["runs"] = runs
        meta["successes"] = successes
        meta["success_rate"] = round(successes / runs, 3) if runs else None
        if not success and reason:
            pf = list(meta.get("pitfalls", []))
            r = reason.strip()[:200]
            if r and r not in pf:
                pf.append(r)
            meta["pitfalls"] = pf[-MAX_PITFALLS:]
        g.add_node(pid, "Persona", role, content=content, meta=meta)
        return meta
    except Exception:
        return {}


def persona_stats(role: str) -> dict:
    """{runs, success_rate, pitfalls} — 없으면 빈 값."""
    try:
        node = _graph().get_node(f"persona:{role}")
        if not node:
            return {"runs": 0, "success_rate": None, "pitfalls": []}
        meta = _as_dict(node.get("meta"))
        return {"runs": int(meta.get("runs", 0)),
                "success_rate": meta.get("success_rate"),
                "pitfalls": list(meta.get("pitfalls", []))}
    except Exception:
        return {"runs": 0, "success_rate": None, "pitfalls": []}


def apply_feedback(persona) -> "object":
    """과거 성과/교훈을 페르소나에 반영(in-place). 교훈 주입 + 모델 티어 조정.

    persona 는 harness.Persona. load_personas 가 매 생성마다 새 객체를 주므로 in-place 변형 안전.
    반환: 같은 persona(편의상). meta 에 runs/success_rate/tier_adjusted 기록.
    """
    st = persona_stats(persona.role)
    runs, rate, pitfalls = st["runs"], st["success_rate"], st["pitfalls"]

    # 1) 교훈 주입 — 품질 자체 검증 섹션에 과거 실패 교훈 append
    if pitfalls:
        note = "\n".join(f"- (과거 실패 교훈) {p}" for p in pitfalls)
        persona.prompt = dict(persona.prompt or {})
        prev = persona.prompt.get("quality_self_check", "")
        persona.prompt["quality_self_check"] = (prev + "\n" + note).strip()

    # 2) 모델 티어 조정 정책
    orig = persona.model_tier
    new_tier = orig
    force_verify = False
    if rate is not None and runs >= PROMOTE_RUNS and rate >= PROMOTE_RATE \
            and orig == "reasoning" and not persona.can_write:
        new_tier = "execution"            # 검증된 읽기전용 → 경량화(비용↓)
    elif rate is not None and runs >= DEMOTE_RUNS and rate < DEMOTE_RATE:
        if orig == "execution":
            new_tier = "reasoning"        # 저성과 → 상향
        force_verify = True               # 저성과 → harness_gen 이 verify 강제
    persona.model_tier = new_tier

    persona.meta = dict(persona.meta or {})
    persona.meta.update({"runs": runs, "success_rate": rate,
                         "tier_from": orig, "tier_to": new_tier,
                         "force_verify": force_verify})
    return persona
