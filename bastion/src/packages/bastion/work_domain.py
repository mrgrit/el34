"""Work domain — 9-tier 계층 (Mission · Vision · Goal · Strategy · KPI · Plan · Todo · Playbook · Experience).

ISMS-P / SOC 운영의 실제 PDCA + OKR 구조와 1:1 매핑. Knowledge Graph 위에
얇게 얹힌 helper. 모든 데이터는 KG 노드/엣지로 저장된다.

3 Tier 분류:
  Strategic  (영구·연 단위) : Mission · Vision · Goal · Strategy · KPI
  Tactical   (분기·월·주)   : Plan (work) · Todo (job)
  Operational (단일 작업)   : Playbook (task) · Experience · History (별도 모듈)

엣지:
  realizes   : 하위 → 상위 ("이 todo 가 어느 plan 을 실현하는가")
  measures   : KPI → Goal/Strategy
  derives_from : Plan → Strategy → Goal → Vision → Mission
  blocks     : 의존 관계
  contributes_to : 다중 부모 (한 task 가 여러 plan 에 기여)
"""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from .graph import get_graph


# Strategic tier 노드 타입
STRATEGIC_TYPES = ("Mission", "Vision", "Goal", "Strategy", "KPI")

# Tactical tier 노드 타입
TACTICAL_TYPES = ("Plan", "Todo")

# Work edge 타입
WORK_EDGES = ("realizes", "measures", "derives_from", "blocks",
              "contributes_to", "owned_by", "scheduled_for")


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# ── Strategic ────────────────────────────────────────────────────────────────

def add_mission(title: str, statement: str, owner: str = "CISO") -> str:
    """Mission — 영구적 정보보호 책임 (예: '사내 정보자산의 기밀성·무결성·가용성 보장')."""
    mid = _new_id("mission")
    g = get_graph()
    g.add_node(mid, "Mission", title,
               content={"statement": statement, "owner": owner},
               meta={"created_at": _now_iso(), "tier": "strategic"})
    return mid


def add_vision(title: str, horizon_year: int, statement: str,
               mission_id: str = "") -> str:
    """Vision — 3-5년 지향점."""
    vid = _new_id("vision")
    g = get_graph()
    g.add_node(vid, "Vision", title,
               content={"horizon_year": horizon_year, "statement": statement},
               meta={"created_at": _now_iso(), "tier": "strategic"})
    if mission_id:
        g.add_edge(vid, mission_id, "derives_from")
    return vid


def add_goal(title: str, due: str, vision_id: str = "",
             description: str = "") -> str:
    """Goal — 1년 목표 (OKR 의 Objective)."""
    gid = _new_id("goal")
    g = get_graph()
    g.add_node(gid, "Goal", title,
               content={"due": due, "description": description},
               meta={"created_at": _now_iso(), "tier": "strategic",
                     "status": "open"})
    if vision_id:
        g.add_edge(gid, vision_id, "derives_from")
    return gid


def add_strategy(title: str, goal_id: str, approach: str = "") -> str:
    """Strategy — 목표 달성 방식 (예: 'zero-trust 기반 접근 제어 도입')."""
    sid = _new_id("strategy")
    g = get_graph()
    g.add_node(sid, "Strategy", title,
               content={"approach": approach},
               meta={"created_at": _now_iso(), "tier": "strategic"})
    if goal_id:
        g.add_edge(sid, goal_id, "derives_from")
    return sid


def add_kpi(name: str, target: float, unit: str = "",
            measures: str = "", goal_id: str = "",
            strategy_id: str = "") -> str:
    """KPI — 측정 지표. 측정값은 별도 record_kpi(value, ts) 로 시계열 누적."""
    kid = _new_id("kpi")
    g = get_graph()
    g.add_node(kid, "KPI", name,
               content={"target": target, "unit": unit,
                        "measures": measures, "history": []},
               meta={"created_at": _now_iso(), "tier": "strategic"})
    if goal_id:
        g.add_edge(kid, goal_id, "measures")
    if strategy_id:
        g.add_edge(kid, strategy_id, "measures")
    return kid


def record_kpi(kpi_id: str, value: float, ts: str = "",
               note: str = "") -> dict:
    """KPI 측정값 추가 (시계열). content.history 에 누적 + History event 도 기록."""
    g = get_graph()
    node = g.get_node(kpi_id)
    if not node:
        return {"error": f"kpi {kpi_id} not found"}
    content = node.get("content") or {}
    history = content.get("history") or []
    entry = {"ts": ts or _now_iso(), "value": value, "note": note}
    history.append(entry)
    content["history"] = history[-200:]  # 최근 200개만
    g.add_node(kpi_id, "KPI", node.get("name", ""),
               content=content, meta=node.get("meta") or {})
    # History layer 에도 기록 (장기 보존)
    try:
        from .history import HistoryLayer
        h = HistoryLayer()
        h.add_event(
            kind="kpi_measurement",
            summary=f"{node.get('name','')} = {value}{content.get('unit','')}",
            asset_id=kpi_id,
            payload={"kpi_id": kpi_id, "value": value, "note": note},
        )
    except Exception:
        pass
    return {"kpi_id": kpi_id, "entry": entry, "total_records": len(history)}


# ── Tactical ─────────────────────────────────────────────────────────────────

def add_plan(title: str, period: str, owner: str = "",
             strategy_id: str = "", goal_id: str = "",
             description: str = "") -> str:
    """Plan (work) — 분기·월 단위 작업 묶음."""
    pid = _new_id("plan")
    g = get_graph()
    g.add_node(pid, "Plan", title,
               content={"period": period, "owner": owner,
                        "description": description},
               meta={"created_at": _now_iso(), "tier": "tactical",
                     "status": "open"})
    if strategy_id:
        g.add_edge(pid, strategy_id, "derives_from")
    if goal_id:
        g.add_edge(pid, goal_id, "contributes_to")
    return pid


def add_todo(title: str, due: str, plan_id: str = "",
             assignee: str = "", description: str = "") -> str:
    """Todo (job) — 일·주 단위 실행 항목."""
    tid = _new_id("todo")
    g = get_graph()
    g.add_node(tid, "Todo", title,
               content={"due": due, "assignee": assignee,
                        "description": description},
               meta={"created_at": _now_iso(), "tier": "tactical",
                     "status": "open"})
    if plan_id:
        g.add_edge(tid, plan_id, "realizes")
    return tid


def update_status(node_id: str, status: str, note: str = "") -> dict:
    """Plan/Todo/Goal 상태 변경. status ∈ {open, in_progress, completed, blocked, cancelled}."""
    g = get_graph()
    node = g.get_node(node_id)
    if not node:
        return {"error": "not found"}
    meta = node.get("meta") or {}
    meta["status"] = status
    meta["status_updated_at"] = _now_iso()
    if note:
        meta["status_note"] = note
    g.add_node(node_id, node.get("type", ""), node.get("name", ""),
               content=node.get("content") or {}, meta=meta)
    # 진행 사실 History event
    try:
        from .history import HistoryLayer
        HistoryLayer().add_event(
            kind="work_status_change",
            summary=f"{node.get('type','')} {node.get('name','')[:40]} → {status}",
            asset_id=node_id,
            payload={"status": status, "note": note},
        )
    except Exception:
        pass
    return {"node_id": node_id, "status": status}


# ── 통합 조회 ────────────────────────────────────────────────────────────────

def trace_to_mission(node_id: str, max_depth: int = 8) -> dict:
    """임의 todo/plan/playbook 부터 위로 traverse → mission 까지 chain.

    "이 작업이 어느 mission 에 기여하는가" 답.
    """
    g = get_graph()
    try:
        chain = g.traverse(node_id, max_depth=max_depth,
                           edge_types=["realizes", "derives_from",
                                       "contributes_to"])
    except Exception as e:
        return {"error": str(e)}
    nodes = list(chain.values())
    by_type = {}
    for n in nodes:
        by_type.setdefault(n.get("type", ""), []).append(n)
    return {
        "start": node_id,
        "depth": max_depth,
        "node_count": len(nodes),
        "by_tier": {
            "strategic": [n for n in nodes if n.get("type") in STRATEGIC_TYPES],
            "tactical": [n for n in nodes if n.get("type") in TACTICAL_TYPES],
            "operational": [n for n in nodes if n.get("type") in ("Playbook", "Experience")],
        },
        "by_type_count": {t: len(v) for t, v in by_type.items()},
    }


def strategic_dashboard() -> dict:
    """Mission/Vision/Goal/Strategy 의 KPI 진행 한눈에."""
    g = get_graph()
    out = {"missions": [], "open_goals": 0, "active_strategies": 0, "kpis": []}
    out["missions"] = g.find_nodes(type="Mission", limit=20)
    goals = g.find_nodes(type="Goal", limit=100)
    out["open_goals"] = sum(1 for x in goals
                             if (x.get("meta") or {}).get("status") != "completed")
    out["active_strategies"] = len(g.find_nodes(type="Strategy", limit=100))
    kpis = g.find_nodes(type="KPI", limit=50)
    for k in kpis:
        c = k.get("content") or {}
        history = c.get("history") or []
        latest = history[-1] if history else None
        out["kpis"].append({
            "id": k.get("id"),
            "name": k.get("name"),
            "target": c.get("target"),
            "unit": c.get("unit", ""),
            "latest": latest,
            "trend": [h.get("value") for h in history[-10:]],
        })
    return out


__all__ = [
    "add_mission", "add_vision", "add_goal", "add_strategy",
    "add_kpi", "record_kpi",
    "add_plan", "add_todo", "update_status",
    "trace_to_mission", "strategic_dashboard",
    "STRATEGIC_TYPES", "TACTICAL_TYPES", "WORK_EDGES",
]
