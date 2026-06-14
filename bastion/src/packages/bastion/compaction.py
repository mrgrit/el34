"""Bastion Experience Compaction — KG-5

목적 (사용자 명시): 자잘한 experience 는 폐기, 비슷한 건 묶음, 검증된 노하우만
정제된 형태로 영구 보존. playbook 의 known_pitfalls 자동 갱신.

흐름:
  1. 같은 playbook 의 derived experience 모음 (≥ MIN_EXPERIENCES)
  2. LLM 에 보내서 압축 → JSON: {pitfalls, recovery_patterns, insights, drop_ids}
  3. Insight 노드 생성 + abstracts 엣지 (→ source experiences)
  4. playbook.known_pitfalls 업데이트 + 그래프 노드 content 동기화
  5. drop_ids 표시된 노이즈 experience 는 meta.deprecated=true (delete 안 함, audit)

주기:
  - 운영자 수동 트리거 (CLI / API)
  - agent.chat N회마다 자동 (실험)
  - 시간 기반 cron (운영 환경)
"""
from __future__ import annotations

import json
import time
from typing import Any

import httpx

from packages.bastion.graph import get_graph


MIN_EXPERIENCES = 5         # 압축 시도 최소 experience 수
MIN_FAIL_RECURRENCE = 2     # 같은 error 가 N회 이상 보여야 known_pitfall 로 승격
NOISE_AGE_DAYS = 1          # 1일 이내 1회만 발생한 fail 은 노이즈 후보


def _build_compaction_prompt(playbook: dict, experiences: list[dict]) -> str:
    """LLM 압축 프롬프트 작성."""
    pb_summary = (
        f"playbook_id: {playbook.get('id')}\n"
        f"name: {playbook.get('name', '')}\n"
        f"description: {(playbook.get('content') or {}).get('description', '')[:200]}\n"
    )
    exp_summaries = []
    for e in experiences[:30]:  # 너무 많으면 prompt 폭발 — 최근 30개만
        c = e.get("content") or {}
        outcome = c.get("outcome", "unknown")
        tools = c.get("tool_outputs", [])[:3]
        tool_summary = "; ".join(
            f"{t.get('skill')}:{ 'OK' if t.get('success') else 'FAIL'}({str(t.get('output_head',''))[:80]})"
            for t in tools
        )
        exp_summaries.append(
            f"- [{e.get('id')}] outcome={outcome} | tools: {tool_summary} | "
            f"task: {c.get('task_summary','')[:120]}"
        )
    parts = [
        "보안 운영 에이전트의 experience 집합을 보고 정제·압축하라.",
        "출력은 아래 형식의 JSON 한 객체만 (코드블록·설명문 금지):",
        '{"pitfalls": [{"text":"...","evidence_count":N,"sources":["exp-..."]}],',
        ' "recovery_patterns": [{"error":"...","recovery":"...","sources":["exp-..."]}],',
        ' "insights": [{"text":"...","sources":["exp-..."]}],',
        ' "drop_ids": ["exp-..."],',
        ' "summary": "한 단락 종합"}',
        "",
        "## 정제 원칙",
        "- pitfalls: 2회 이상 반복 발생한 실패 패턴 (1회성 fail 은 drop_ids 로)",
        "- recovery_patterns: error 와 그 회피책 쌍 (적용해서 풀린 사례 있을 때만)",
        "- insights: 비슷한 작업의 노하우·관찰·시간 패턴 등 (예: 'weekday 평균 3.2s')",
        "- drop_ids: 1회만 발생 + 재현 안 된 fail, 또는 정보가 너무 빈약한 노이즈",
        "- 모든 항목은 sources (해당 exp_id) 명시 — 추적 가능해야 함",
        "",
        f"## 대상 Playbook\n{pb_summary}",
        "## 실행 사례 (최근 30건)",
        "\n".join(exp_summaries),
        "",
        "정제된 결과를 JSON 으로 출력하라.",
    ]
    return "\n".join(parts)


def compact_playbook(playbook_id: str,
                     ollama_url: str = "",
                     model: str = "",
                     min_experiences: int = MIN_EXPERIENCES) -> dict:
    """주어진 playbook 의 experience 정제 → Insight 노드 생성 + known_pitfalls 갱신.

    반환: {playbook_id, experiences_examined, insights_created, pitfalls_added,
           dropped, errors}
    """
    g = get_graph()
    pb_node = g.get_node(playbook_id)
    if not pb_node or pb_node.get("type") != "Playbook":
        return {"error": f"playbook not found: {playbook_id}"}

    # 1. derived experiences
    in_edges = g.neighbors(playbook_id, edge_type="derived_from", direction="in")
    exp_ids = [e["other"] for e in in_edges]
    if len(exp_ids) < min_experiences:
        return {"playbook_id": playbook_id,
                "skipped": True,
                "reason": f"experiences {len(exp_ids)} < min {min_experiences}"}

    # 2. 풀 콘텐츠 로드
    experiences = [g.get_node(eid) for eid in exp_ids]
    experiences = [e for e in experiences if e]

    # 3. LLM 압축
    if not ollama_url or not model:
        from packages.bastion import LLM_BASE_URL, LLM_MANAGER_MODEL
        ollama_url = ollama_url or LLM_BASE_URL
        model = model or LLM_MANAGER_MODEL
    prompt = _build_compaction_prompt(pb_node, experiences)
    try:
        r = httpx.post(
            f"{ollama_url}/api/chat",
            json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0, "num_predict": 2000},
            },
            timeout=120.0,
        )
        content = r.json().get("message", {}).get("content", "")
        result = json.loads(content) if content else {}
    except Exception as e:
        return {"playbook_id": playbook_id, "error": f"LLM compaction failed: {e}"}

    pitfalls = result.get("pitfalls", []) or []
    recoveries = result.get("recovery_patterns", []) or []
    insights = result.get("insights", []) or []
    drop_ids = result.get("drop_ids", []) or []
    summary = result.get("summary", "")

    # 4. Insight 노드 생성 + abstracts 엣지
    ts = time.strftime("%Y%m%d-%H%M%S")
    insights_created = 0
    for i, ins in enumerate(insights[:20]):
        if not isinstance(ins, dict):
            continue
        text = (ins.get("text") or "").strip()
        sources = ins.get("sources") or []
        if not text:
            continue
        ins_id = f"insight-{playbook_id}-{ts}-{i}"
        g.add_node(
            ins_id, "Insight", text[:120],
            content={"text": text, "sources": sources,
                     "playbook_id": playbook_id, "kind": "insight"},
            meta={"playbook_id": playbook_id,
                  "evidence_count": len(sources),
                  "kind": "insight"},
        )
        for src in sources[:10]:
            if g.get_node(src):
                g.add_edge(ins_id, src, "abstracts")
        insights_created += 1

    # recovery patterns → Insight + Recovery + applied_in 엣지 (단순화: Insight 로 통합)
    for i, rec in enumerate(recoveries[:20]):
        if not isinstance(rec, dict):
            continue
        err = (rec.get("error") or "").strip()
        recovery = (rec.get("recovery") or "").strip()
        if not (err and recovery):
            continue
        sources = rec.get("sources") or []
        # Error 노드
        err_id = f"error-{playbook_id}-{abs(hash(err)) % 10**8}"
        g.add_node(err_id, "Error", err[:80],
                   content={"text": err, "playbook_id": playbook_id},
                   meta={"playbook_id": playbook_id})
        # Recovery 노드
        rec_id = f"recovery-{playbook_id}-{abs(hash(recovery)) % 10**8}"
        g.add_node(rec_id, "Recovery", recovery[:80],
                   content={"text": recovery, "playbook_id": playbook_id},
                   meta={"playbook_id": playbook_id})
        g.add_edge(err_id, rec_id, "recovered_by")
        # source experiences → Error 매핑
        for src in sources[:5]:
            if g.get_node(src):
                g.add_edge(src, err_id, "encountered")
                g.add_edge(rec_id, src, "applied_in")

    # 5. playbook.known_pitfalls 업데이트 (graph 노드 content + YAML)
    pitfall_texts = []
    for p in pitfalls[:10]:
        if isinstance(p, dict) and p.get("text"):
            pitfall_texts.append(p["text"][:200])
        elif isinstance(p, str):
            pitfall_texts.append(p[:200])
    if pitfall_texts:
        # 그래프 노드 content 갱신
        existing_content = pb_node.get("content") or {}
        merged = list({*existing_content.get("known_pitfalls", []), *pitfall_texts})[:15]
        existing_content["known_pitfalls"] = merged
        existing_content["last_compaction"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        existing_content["compaction_summary"] = summary[:500]
        g.add_node(playbook_id, "Playbook", pb_node.get("name", ""),
                   content=existing_content, meta=pb_node.get("meta", {}))
        # YAML 도 갱신
        try:
            from packages.bastion.playbook import write_playbook, load_playbook
            pid = playbook_id.replace("pb-", "", 1)
            pb_yaml = load_playbook(pid)
            if pb_yaml:
                pb_yaml["known_pitfalls"] = merged
                pb_yaml["last_compaction"] = existing_content["last_compaction"]
                pb_yaml["compaction_summary"] = summary[:500]
                # version 증가하지 않음 — content 보강만
                write_playbook(pb_yaml)
        except Exception:
            pass

    # 6. 노이즈 표시 (delete 안 함 — audit 위해 보존, deprecated meta 만)
    # History anchor 면역 게이트 — anchor 와 매칭되거나 narrative 에 속한 experience 는 보존.
    try:
        from packages.bastion.history import HistoryLayer, is_compaction_immune
        _history = HistoryLayer()
    except Exception:
        _history = None

    dropped = 0
    immune = 0
    for did in drop_ids[:30]:
        node = g.get_node(did)
        if not (node and node.get("type") == "Experience"):
            continue
        # anchor / narrative 면역 검사
        if _history is not None:
            try:
                if is_compaction_immune(_history, did, node.get("name", "") or ""):
                    immune += 1
                    continue
            except Exception:
                pass
        meta = node.get("meta") or {}
        meta["deprecated"] = True
        meta["deprecated_reason"] = "compaction noise"
        meta["deprecated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        g.add_node(did, "Experience", node.get("name", ""),
                   content=node.get("content"), meta=meta)
        dropped += 1

    return {
        "playbook_id": playbook_id,
        "experiences_examined": len(experiences),
        "pitfalls_added": len(pitfall_texts),
        "recoveries_added": len(recoveries),
        "insights_created": insights_created,
        "dropped": dropped,
        "history_immune": immune,
        "summary": summary[:200],
    }


def compact_all(min_experiences: int = MIN_EXPERIENCES,
                limit_playbooks: int = 50,
                ollama_url: str = "",
                model: str = "") -> dict:
    """모든 playbook 에 대해 compaction 시도. 각 결과 누적."""
    g = get_graph()
    pbs = g.find_nodes(type="Playbook", limit=limit_playbooks)
    results = []
    for pb in pbs:
        result = compact_playbook(pb["id"],
                                  ollama_url=ollama_url, model=model,
                                  min_experiences=min_experiences)
        results.append(result)
    summary = {
        "playbooks_examined": len(results),
        "playbooks_compacted": sum(1 for r in results if not r.get("skipped") and not r.get("error")),
        "skipped": sum(1 for r in results if r.get("skipped")),
        "errors": sum(1 for r in results if r.get("error")),
        "total_insights": sum(r.get("insights_created", 0) for r in results),
        "total_pitfalls": sum(r.get("pitfalls_added", 0) for r in results),
        "total_dropped": sum(r.get("dropped", 0) for r in results),
        "details": results,
    }
    return summary


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] != "all":
        print(json.dumps(compact_playbook(sys.argv[1]), indent=2, ensure_ascii=False))
    else:
        print(json.dumps(compact_all(), indent=2, ensure_ascii=False))
