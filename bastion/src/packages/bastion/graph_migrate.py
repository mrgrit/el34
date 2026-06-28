"""기존 자료를 KnowledgeGraph 로 1회 마이그레이션.

소스:
  - Playbook YAML (PLAYBOOKS_DIR)
  - SKILLS dict (skills.py)
  - 기존 experience.db (있으면)

산출:
  - Playbook 노드 + uses(→Skill) 엣지
  - Skill 노드
  - Asset 노드 (VM role 5개) + targets 엣지 (playbook 의 target 추론)
  - Experience 노드 + derived_from(→Playbook), targets(→Asset) 엣지
  - Concept 노드 (experience.classify 의 카테고리)

idempotent — 다시 돌려도 OK (ON CONFLICT 처리됨).
"""
from __future__ import annotations

import glob
import json
import os
import sqlite3
import yaml

from bastion.graph import get_graph
from bastion.playbook import PLAYBOOKS_DIR
from bastion.skills import SKILLS

# experience 카테고리 룰 재사용
try:
    from bastion.experience import CATEGORY_RULES
except ImportError:
    CATEGORY_RULES = []


VM_ROLES = {
    "attacker": "10.20.30.201",
    "secu":     "10.20.30.1",
    "web":      "10.20.30.80",
    "siem":     "10.20.30.100",
    "manager":  "10.20.30.200",
}


def migrate_skills(g) -> int:
    """SKILLS dict → Skill 노드."""
    n = 0
    for name, sk in SKILLS.items():
        node_id = f"skill-{name}"
        g.add_node(
            node_id, "Skill", name,
            content={
                "description": sk.get("description", ""),
                "params": sk.get("params", {}),
                "target_vm": sk.get("target_vm", "auto"),
                "requires_approval": sk.get("requires_approval", False),
            },
            meta={"requires_approval": sk.get("requires_approval", False)},
        )
        n += 1
    return n


def migrate_assets(g) -> int:
    """5 VM role → Asset 노드."""
    n = 0
    for role, ip in VM_ROLES.items():
        g.add_node(
            f"asset-vm-{role}", "Asset", f"{role} VM",
            content={"role": role, "ip": ip, "kind": "vm"},
            meta={"kind": "vm", "role": role, "ip": ip},
        )
        n += 1
    return n


def migrate_concepts(g) -> int:
    """experience CATEGORY_RULES → Concept 노드."""
    n = 0
    seen = set()
    for _, cat in CATEGORY_RULES:
        if cat in seen:
            continue
        seen.add(cat)
        g.add_node(
            f"concept-{cat}", "Concept", cat,
            content={"kind": "category", "source": "experience.CATEGORY_RULES"},
            meta={"kind": "ops_category"},
        )
        n += 1
    return n


def _classify(message: str) -> str | None:
    for pat, cat in CATEGORY_RULES:
        if pat.search(message):
            return cat
    return None


def _infer_targets(playbook: dict) -> set[str]:
    """playbook 의 steps 에서 target VM role 추출."""
    roles = set()
    for step in playbook.get("steps", []):
        if not isinstance(step, dict):
            continue
        params = step.get("params") or {}
        t = params.get("target") or params.get("target_vm") or step.get("target_vm")
        if isinstance(t, str) and t in VM_ROLES:
            roles.add(t)
    return roles


def migrate_playbooks(g) -> tuple[int, int]:
    """Playbook YAML 파일 → Playbook 노드 + uses/targets 엣지."""
    n_nodes = 0
    n_edges = 0
    for f in sorted(glob.glob(os.path.join(PLAYBOOKS_DIR, "*.yaml"))):
        try:
            with open(f, encoding="utf-8") as fh:
                pb = yaml.safe_load(fh)
        except Exception:
            continue
        if not pb or not isinstance(pb, dict):
            continue
        pb_id = pb.get("playbook_id") or os.path.basename(f).replace(".yaml", "")
        node_id = f"pb-{pb_id}" if not pb_id.startswith("pb-") else pb_id
        name = pb.get("name") or pb.get("title") or pb_id

        # 노드 콘텐츠
        content = {
            "playbook_id": pb_id,
            "name": name,
            "description": pb.get("description", ""),
            "version": pb.get("version", 1),
            "risk_level": pb.get("risk_level", "low"),
            "reasoning": pb.get("reasoning", {}),       # KG-2 확장 필드
            "plan": pb.get("plan", pb.get("steps", [])),
            "known_pitfalls": pb.get("known_pitfalls", []),
            "exec_history": pb.get("exec_history", {}),
            "source_file": os.path.basename(f),
        }
        meta = {
            "version": pb.get("version", 1),
            "risk_level": pb.get("risk_level", "low"),
            "exec_total": pb.get("exec_history", {}).get("total", 0),
            "exec_success": pb.get("exec_history", {}).get("success", 0),
        }
        g.add_node(node_id, "Playbook", name, content=content, meta=meta)
        n_nodes += 1

        # uses → Skill
        for step in pb.get("steps", []) or pb.get("plan", []):
            if not isinstance(step, dict):
                continue
            sk = step.get("skill")
            if isinstance(sk, str) and sk in SKILLS:
                g.add_edge(node_id, f"skill-{sk}", "uses")
                n_edges += 1

        # targets → Asset
        for role in _infer_targets(pb):
            g.add_edge(node_id, f"asset-vm-{role}", "targets")
            n_edges += 1

        # handles → Concept (description 기반 카테고리 추론)
        text_for_cat = " ".join([
            name, pb.get("description", ""),
            " ".join(str(s) for s in (pb.get("steps") or pb.get("plan") or [])),
        ])
        cat = _classify(text_for_cat)
        if cat:
            g.add_edge(node_id, f"concept-{cat}", "handles")
            n_edges += 1
    return n_nodes, n_edges


def migrate_experience_db(g, db_path: str = "") -> tuple[int, int]:
    """기존 experience.db (sqlite) → Experience 노드 + 엣지."""
    if not db_path:
        # 위치 자동 감지
        here = os.path.dirname(__file__)
        candidates = [
            os.path.join(here, "..", "..", "data", "bastion_experience.db"),
            os.path.join(here, "..", "data", "bastion_experience.db"),
            "/tmp/bastion_experience.db",
        ]
        for c in candidates:
            if os.path.isfile(c):
                db_path = c
                break
    if not db_path or not os.path.isfile(db_path):
        return 0, 0

    n_nodes = 0
    n_edges = 0
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM experience").fetchall()
    except Exception:
        return 0, 0

    for r in rows:
        try:
            d = dict(r)
        except Exception:
            continue
        exp_id = f"exp-legacy-{d.get('id', n_nodes)}"
        category = d.get("category") or _classify(d.get("command_template", "") or "")
        target_vm = d.get("target_vm") or ""
        skill = d.get("skill") or ""

        content = {
            "task_summary": d.get("command_template", "")[:200],
            "category": category,
            "skill": skill,
            "target_vm": target_vm,
            "outcome": "success" if (d.get("success_count", 0) > d.get("fail_count", 0)) else "fail",
            "stats": {
                "success_count": d.get("success_count", 0),
                "fail_count": d.get("fail_count", 0),
                "total_count": d.get("total_count", 0),
            },
            "examples": json.loads(d.get("examples") or "[]"),
            "keywords": json.loads(d.get("keywords") or "[]"),
            "created_at": d.get("created_at", ""),
            "last_used": d.get("last_used", ""),
            "_legacy_id": d.get("id"),
        }
        meta = {
            "outcome": content["outcome"],
            "category": category,
            "success_rate": (d.get("success_count", 0) /
                             max(d.get("total_count", 1), 1)),
        }
        g.add_node(exp_id, "Experience", f"{category}: {skill}",
                   content=content, meta=meta)
        n_nodes += 1

        # derived_from — 가장 가까운 playbook 매칭은 skill+category 기준
        # (없으면 일반 카테고리 concept 만 연결)
        if skill and skill in SKILLS:
            g.add_edge(exp_id, f"skill-{skill}", "uses")
            n_edges += 1
        if target_vm in VM_ROLES:
            g.add_edge(exp_id, f"asset-vm-{target_vm}", "targets")
            n_edges += 1
        if category:
            g.add_edge(exp_id, f"concept-{category}", "handles")
            n_edges += 1
    return n_nodes, n_edges


def migrate_all(db_path: str = "") -> dict:
    """전체 마이그레이션 실행. 반환: 통계."""
    g = get_graph(db_path)
    skills_n = migrate_skills(g)
    assets_n = migrate_assets(g)
    concepts_n = migrate_concepts(g)
    pb_n, pb_e = migrate_playbooks(g)
    exp_n, exp_e = migrate_experience_db(g)
    return {
        "skills": skills_n,
        "assets": assets_n,
        "concepts": concepts_n,
        "playbooks": pb_n,
        "playbook_edges": pb_e,
        "experiences": exp_n,
        "experience_edges": exp_e,
        "total_nodes": skills_n + assets_n + concepts_n + pb_n + exp_n,
        "total_edges": pb_e + exp_e,
        "graph_path": g.db_path,
    }


if __name__ == "__main__":
    print(json.dumps(migrate_all(), indent=2, ensure_ascii=False))
