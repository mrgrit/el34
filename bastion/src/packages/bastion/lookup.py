"""Bastion Playbook Lookup — KG-4 결정 로직 (reuse/adapt/new)

설계 (사용자 명시):
  1단계: 키워드 + FTS + 그래프 traversal 로 후보 top-3 수집 (빠름)
  2단계: LLM 결정관 (decision JSON 출력)
  강제 규칙: similarity ≥ 0.92 + success ≥ 80% → strict reuse
            similarity < 0.7 → strict new
            그 사이는 LLM 판단
"""
from __future__ import annotations

import json
import re
from typing import Any

import httpx

from packages.bastion.graph import get_graph


# 강제 결정 임계값
THRESH_REUSE = 0.92          # 이 이상 + 성공률 OK → strict reuse
THRESH_NEW = 0.70            # 이 미만 → strict new
THRESH_SUCCESS_RATE = 0.80   # reuse 시 요구되는 최근 성공률
DESTRUCTIVE_CATEGORIES = {"exploit", "privesc", "credential_attack",
                          "deploy_rule"}  # high-risk: 자동 reuse 금지

# 토큰 추출 (한국어 + 영문)
_TOKEN_RE = re.compile(r"[\w가-힣]+", re.UNICODE)


def _tokens(text: str) -> set[str]:
    return {t.lower() for t in _TOKEN_RE.findall(text or "") if len(t) >= 2}


def _jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / max(len(a | b), 1)


def _coverage(message: str, playbook: dict) -> float:
    """task 의 entity(skill 키워드, target 등) 가 playbook.plan 에 얼마나 포함되나."""
    msg_tokens = _tokens(message)
    plan = playbook.get("plan") or playbook.get("steps") or []
    pb_tokens: set[str] = set()
    for step in plan:
        if not isinstance(step, dict):
            continue
        pb_tokens |= _tokens(step.get("intent", ""))
        pb_tokens |= _tokens(str(step.get("skill", "")))
        for v in (step.get("params") or {}).values():
            if isinstance(v, str):
                pb_tokens |= _tokens(v)
    pb_tokens |= _tokens(playbook.get("name", ""))
    pb_tokens |= _tokens(playbook.get("description", ""))
    return _jaccard(msg_tokens, pb_tokens)


def _success_rate(playbook: dict) -> float:
    eh = playbook.get("exec_history") or {}
    total = int(eh.get("total", 0))
    success = int(eh.get("success", 0))
    if total < 1:
        return 0.5  # 미실행 → 중립
    return success / total


def collect_candidates(message: str, top_k: int = 3) -> list[dict]:
    """단계 1 — 키워드 + FTS + 그래프 인접 노드 로 Playbook 후보 수집.

    각 후보: {playbook(dict), similarity, success_rate, coverage, last_used}
    """
    g = get_graph()
    msg_tokens = _tokens(message)
    candidates: dict[str, dict] = {}

    # FTS 쿼리 (높은 유사도 후보)
    query_terms = [t for t in msg_tokens if len(t) >= 3][:8]
    if query_terms:
        try:
            for n in g.search_fts(" OR ".join(query_terms), type="Playbook", limit=10):
                pb = n.get("content") or {}
                if not pb.get("playbook_id"):
                    continue
                candidates[n["id"]] = {
                    "node": n,
                    "playbook": pb,
                    "fts_rank": True,
                }
        except Exception:
            pass

    # 모든 Playbook 도 후보로 (키워드 매칭으로 점수만)
    for n in g.find_nodes(type="Playbook", limit=200):
        if n["id"] in candidates:
            continue
        pb = n.get("content") or {}
        if not pb.get("playbook_id"):
            continue
        candidates[n["id"]] = {"node": n, "playbook": pb, "fts_rank": False}

    # 점수 계산
    scored = []
    for cid, c in candidates.items():
        pb = c["playbook"]
        pb_text = " ".join([
            pb.get("name", ""),
            pb.get("description", ""),
            " ".join((s.get("intent", "") if isinstance(s, dict) else "")
                     for s in pb.get("plan", [])),
        ])
        sim = _jaccard(msg_tokens, _tokens(pb_text))
        # FTS 매칭이면 가산점
        if c["fts_rank"]:
            sim = min(1.0, sim + 0.15)
        cov = _coverage(message, pb)
        sr = _success_rate(pb)
        scored.append({
            "id": cid,
            "playbook": pb,
            "similarity": round(sim, 3),
            "coverage": round(cov, 3),
            "success_rate": round(sr, 3),
            "version": pb.get("version", 1),
            "exec_total": (pb.get("exec_history") or {}).get("total", 0),
        })

    # similarity * 0.6 + coverage * 0.3 + success * 0.1 로 정렬
    scored.sort(
        key=lambda x: x["similarity"] * 0.6 + x["coverage"] * 0.3 + x["success_rate"] * 0.1,
        reverse=True,
    )
    return scored[:top_k]


def hard_decision(top_candidates: list[dict], message: str) -> dict | None:
    """강제 규칙 — LLM 호출 전 명백한 케이스 즉시 결정.

    반환: decision dict 또는 None (None 이면 LLM verifier 호출 필요)
    """
    if not top_candidates:
        return {"decision": "new", "reason": "후보 없음 — 신규 작업"}

    top = top_candidates[0]
    # 명백 reuse: similarity 매우 높음 + 성공률 OK + coverage OK
    if (top["similarity"] >= THRESH_REUSE and
            top["success_rate"] >= THRESH_SUCCESS_RATE and
            top["coverage"] >= 0.85 and
            top["exec_total"] >= 2):
        # 단, destructive 면 강제 reuse 금지 (사람 승인 또는 LLM 검증 필요)
        cat = (top["playbook"].get("related_concepts") or [None])[0]
        if cat not in DESTRUCTIVE_CATEGORIES:
            return {
                "decision": "reuse",
                "playbook_id": top["playbook"].get("playbook_id"),
                "confidence": top["similarity"],
                "reason": "강제 reuse — 명백한 동일 작업 (sim≥0.92, success≥80%)",
                "candidate": top,
            }
    # 명백 new: 모든 후보가 너무 약함
    if top["similarity"] < THRESH_NEW:
        return {
            "decision": "new",
            "reason": f"강제 new — 최고 후보도 sim={top['similarity']} < {THRESH_NEW}",
            "candidate": None,
        }
    # 망가진 playbook: success_rate 너무 낮으면 reuse 금지
    if top["success_rate"] < 0.5 and top["exec_total"] >= 5:
        return {
            "decision": "adapt",
            "playbook_id": top["playbook"].get("playbook_id"),
            "confidence": top["similarity"],
            "reason": f"강제 adapt — 후보 success_rate={top['success_rate']} 낮음, 보정 필요",
            "candidate": top,
        }
    return None  # LLM verifier 가 결정


def llm_verifier(message: str, candidates: list[dict],
                 ollama_url: str, model: str) -> dict:
    """단계 2 — LLM 이 task vs 후보 보고 reuse/adapt/new 결정."""
    parts = [
        "보안 운영 에이전트의 작업 lookup 결정관이다.",
        "새 task 와 기존 playbook 후보를 보고 reuse / adapt / new 중 결정하라.",
        "",
        "## 출력 (JSON 한 객체만, 코드블록 없이)",
        '{"decision": "reuse"|"adapt"|"new",',
        ' "playbook_id": "...", "confidence": 0.0~1.0, "reason": "한 줄",',
        ' "adaptations": [{"step": int, "change": "...", "why": "..."}]}',
        "",
        "## 결정 기준",
        "- reuse: 같은 작업·동일 도구·동일 의도. 그대로 실행 가능.",
        "- adapt: 비슷하지만 파라미터·일부 step 변경 필요. adaptations 명시.",
        "- new: 후보 전부 부적합. 신규 plan 필요. playbook_id 빈 문자열, adaptations 비움.",
        "",
        f"## 새 task\n{message[:500]}",
        "",
        "## 후보 (top-3)",
    ]
    for i, c in enumerate(candidates[:3], 1):
        pb = c["playbook"]
        plan_summary = "\n".join(
            f"     {s.get('step', j)}. {s.get('skill', '')} — {s.get('intent', '')[:80]}"
            for j, s in enumerate(pb.get("plan") or pb.get("steps") or [], 1)
            if isinstance(s, dict)
        )[:600]
        parts.extend([
            f"### 후보 {i}: {pb.get('playbook_id', '?')}",
            f"  name: {pb.get('name', '')}",
            f"  description: {pb.get('description', '')[:160]}",
            f"  similarity: {c['similarity']}, coverage: {c['coverage']}, "
            f"success_rate: {c['success_rate']}, exec_total: {c['exec_total']}",
            f"  plan:\n{plan_summary}",
            "",
        ])
    parts.append("결정하라.")
    prompt = "\n".join(parts)
    try:
        r = httpx.post(
            f"{ollama_url}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0, "num_predict": 600},
            },
            timeout=30.0,
        )
        content = r.json().get("message", {}).get("content", "")
        if not content:
            return {"decision": "new", "reason": "LLM 응답 비어있음"}
        parsed = json.loads(content)
        return {
            "decision": str(parsed.get("decision", "new")).lower(),
            "playbook_id": parsed.get("playbook_id", ""),
            "confidence": float(parsed.get("confidence", 0)),
            "reason": parsed.get("reason", ""),
            "adaptations": parsed.get("adaptations", []),
        }
    except Exception as e:
        return {"decision": "new", "reason": f"LLM 호출 실패: {e}"}


def decide(message: str, ollama_url: str, model: str) -> dict:
    """전체 결정 흐름 — 후보 수집 → hard rule → 필요시 LLM verifier.

    반환: {
        decision: reuse|adapt|new,
        playbook_id: "..." (reuse/adapt 시),
        confidence: 0~1,
        reason: "...",
        adaptations: [...] (adapt 시),
        candidate: {...} (top 후보, log 용),
        candidates: [...] (top-3 전체),
    }
    """
    candidates = collect_candidates(message, top_k=3)
    hard = hard_decision(candidates, message)
    if hard:
        result = dict(hard)
        result["candidates"] = candidates
        return result
    # LLM 으로 위임
    result = llm_verifier(message, candidates, ollama_url, model)
    result["candidates"] = candidates
    if result.get("decision") in ("reuse", "adapt") and not result.get("candidate"):
        # LLM 이 가리킨 playbook_id 매칭
        for c in candidates:
            if c["playbook"].get("playbook_id") == result.get("playbook_id"):
                result["candidate"] = c
                break
        if not result.get("candidate") and candidates:
            result["candidate"] = candidates[0]
    return result


def build_lookup_prompt(decision: dict) -> str:
    """결정 결과를 ReAct system prompt 에 inject 할 텍스트 생성."""
    d = decision.get("decision", "new")
    if d == "new":
        return ""  # 자유롭게 plan 짜라
    cand = decision.get("candidate") or {}
    pb = cand.get("playbook", {})
    if not pb:
        return ""
    plan = pb.get("plan") or pb.get("steps") or []
    plan_text = "\n".join(
        f"  Step {s.get('step', j)}: skill={s.get('skill', '')} — {s.get('intent', '')[:120]}"
        + (f"\n    thinking: {s.get('thinking', '')[:200]}" if s.get('thinking') else "")
        for j, s in enumerate(plan, 1) if isinstance(s, dict)
    )
    reasoning = pb.get("reasoning") or {}
    why = reasoning.get("why_this_approach", "")[:300]
    pitfalls = "\n".join(f"    - {p}" for p in (pb.get("known_pitfalls") or [])[:5])
    if d == "reuse":
        intro = (
            "[lookup] 기존 검증된 playbook 매칭됨 — 그대로 실행하라.\n"
            f"playbook: {pb.get('playbook_id')} (sim={decision.get('confidence', 0):.2f})\n"
        )
        bottom = "\n위 plan 의 도구/파라미터·순서를 유지하되 현재 task 에 맞게 값만 치환하라."
    else:  # adapt
        adaps = decision.get("adaptations") or []
        adap_text = "\n".join(f"    - step {a.get('step', '?')}: {a.get('change', '')} ({a.get('why', '')})"
                              for a in adaps[:5])
        intro = (
            "[lookup] 비슷한 playbook 매칭 (보정 필요).\n"
            f"playbook: {pb.get('playbook_id')} (sim={decision.get('confidence', 0):.2f})\n"
            f"필요한 보정:\n{adap_text or '    (LLM 판단으로 조정)'}\n"
        )
        bottom = "\n위 plan 을 base 로 두되 보정 사항 반영해서 실행하라."
    body = (
        f"[정답 후보 plan]\n{plan_text}\n\n"
        + (f"[근거]\n{why}\n\n" if why else "")
        + (f"[알려진 함정]\n{pitfalls}\n\n" if pitfalls else "")
    )
    return intro + body + bottom
