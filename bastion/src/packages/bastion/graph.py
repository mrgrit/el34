"""Bastion Knowledge Graph — playbook · experience · skill · concept 의 연결망

설계 원칙 (사용자 명시):
  - 동일 작업 = 동일 방법: playbook 이 법, experience 는 보조 노트
  - 정적 lookup 대신 그래프 traversal 로 간접 매칭
  - LLM reasoning + thinking 까지 playbook 안에 박제
  - 자잘한 experience 는 정제·압축, 비슷한 건 묶음

노드 타입:
  Playbook    - 워크플로우 정의 (reasoning + plan + step.thinking 포함)
  Experience  - 실행 기록 (encountered errors / recoveries / new insights)
  Skill       - 원자 도구 (SKILLS dict 동기화)
  Error       - 알려진 실패 패턴 (stderr 시그니처 등)
  Recovery    - error 회피책
  Asset       - 대상 (VM, 파일, 포트, CVE 등)
  Concept     - 추상 개념 (MITRE 기법, 카테고리)
  Insight     - compaction 산출물 (정제된 노하우)

엣지 타입:
  uses          (Playbook → Skill)
  handles       (Playbook → Concept)
  targets       (Playbook → Asset)
  supersedes    (Playbook → Playbook, 신버전이 구버전)
  depends_on    (Playbook → Playbook, 선행 필요)
  often_chains  (Playbook → Playbook, 자주 다음에 옴)
  derived_from  (Experience → Playbook)
  encountered   (Experience → Error)
  recovered_by  (Error → Recovery)
  applied_in    (Recovery → Experience)
  parent_of     (Concept → Concept, 분류체계)
  abstracts     (Insight → Experience, 정제 관계)
"""
from __future__ import annotations

import json
import os
import sqlite3
import time
from typing import Any, Iterable


NODE_TYPES = {
    # Operational tier (PE-KG-H)
    "Playbook", "Experience", "Skill", "Error", "Recovery",
    "Concept", "Insight",
    # History layer (operational 시계열)
    "Narrative", "Anchor",
    # Asset domain
    "Asset",
    # Work domain — Strategic
    "Mission", "Vision", "Goal", "Strategy", "KPI",
    # Work domain — Tactical
    "Plan", "Todo",
}
EDGE_TYPES = {
    # 기존 (operational + KG-4 결정)
    "uses", "handles", "targets", "supersedes", "depends_on",
    "often_chains", "derived_from", "encountered",
    "recovered_by", "applied_in", "parent_of", "abstracts",
    # KG-4 결정 로직
    "reuse", "adapt", "generalize", "refute",
    # History layer
    "precedes", "follows", "belongs_to", "relates_to",
    # Asset / Architecture
    "connects_to", "data_flows_to", "hosts", "manages",
    "trusts", "monitors",
    # Work hierarchy
    "realizes", "measures", "contributes_to", "blocks",
    "owned_by", "scheduled_for", "derives_from",
}


def _resolve_db_path(db_path: str = "") -> str:
    """그래프 DB 경로. CCC 또는 flat 레이아웃 모두 지원.

    우선순위:
      1) 명시 인자
      2) BASTION_GRAPH_DB 환경변수
      3) 기존 DB 발견 (size 큰 순) — 분기 방지
      4) candidate path 의 첫 writable
    """
    if db_path:
        return db_path
    env = os.getenv("BASTION_GRAPH_DB", "").strip()
    if env:
        return env
    here = os.path.dirname(__file__)
    candidates = [
        os.path.normpath(os.path.join(here, "..", "..", "data", "bastion_graph.db")),  # CCC packages/bastion/bastion → ccc/data
        os.path.normpath(os.path.join(here, "..", "..", "..", "data", "bastion_graph.db")),  # 한 단계 더 (/opt/data)
        os.path.normpath(os.path.join(here, "..", "data", "bastion_graph.db")),         # flat (/opt/bastion/data)
        "/home/ccc/ccc/data/bastion_graph.db",  # 명시 absolute (legacy 호환)
    ]
    # 기존 DB 가 있으면 가장 큰 것 선택 (분기 방지 — 2026-04-28 KG drop bug)
    existing = [(c, os.path.getsize(c)) for c in candidates if os.path.isfile(c)]
    if existing:
        existing.sort(key=lambda x: -x[1])
        return existing[0][0]
    # 없으면 첫 writable 위치
    for c in candidates:
        d = os.path.dirname(c)
        if os.path.isdir(d) or os.access(os.path.dirname(d), os.W_OK):
            os.makedirs(d, exist_ok=True)
            return c
    # fallback — /tmp
    return "/tmp/bastion_graph.db"


class KnowledgeGraph:
    """Playbook + Experience + 관련 노드의 그래프 DB 래퍼.

    SQLite 단일 파일 + FTS5 검색 인덱스. 작은 규모(수천 노드)에 충분.
    embedding 은 BLOB 컬럼에 float32 binary — 채워지면 cosine 유사도 사용,
    안 채워지면 FTS 만 사용.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS nodes (
        id          TEXT PRIMARY KEY,
        type        TEXT NOT NULL,
        name        TEXT NOT NULL,
        content     TEXT DEFAULT '{}',
        embedding   BLOB,
        meta        TEXT DEFAULT '{}',
        created_at  TEXT DEFAULT (datetime('now')),
        updated_at  TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
    CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);

    CREATE TABLE IF NOT EXISTS edges (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        src         TEXT NOT NULL,
        dst         TEXT NOT NULL,
        type        TEXT NOT NULL,
        weight      REAL DEFAULT 1.0,
        meta        TEXT DEFAULT '{}',
        created_at  TEXT DEFAULT (datetime('now')),
        UNIQUE(src, dst, type)
    );
    CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src);
    CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst);
    CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(type);

    CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
        id UNINDEXED,
        type UNINDEXED,
        name,
        content_text,
        tokenize='unicode61 remove_diacritics 1'
    );
    """

    def __init__(self, db_path: str = ""):
        self.db_path = _resolve_db_path(db_path)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        return c

    def _init_schema(self):
        with self._conn() as c:
            for stmt in self.SCHEMA.strip().split(";\n"):
                stmt = stmt.strip()
                if stmt:
                    c.execute(stmt)
            c.commit()

    # ── 노드 ──────────────────────────────────────────────────────────

    def add_node(self, node_id: str, type: str, name: str,
                 content: dict | None = None, meta: dict | None = None,
                 embedding: bytes | None = None) -> str:
        if type not in NODE_TYPES:
            raise ValueError(f"unknown node type: {type}")
        content_json = json.dumps(content or {}, ensure_ascii=False)
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        # FTS 용 검색 텍스트 (content 의 reasoning, plan, name 합침)
        fts_text = self._extract_fts_text(name, content or {})
        with self._conn() as c:
            c.execute("""
                INSERT INTO nodes (id, type, name, content, meta, embedding, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
                ON CONFLICT(id) DO UPDATE SET
                    name = excluded.name,
                    content = excluded.content,
                    meta = excluded.meta,
                    embedding = excluded.embedding,
                    updated_at = datetime('now')
            """, (node_id, type, name, content_json, meta_json, embedding))
            c.execute("DELETE FROM nodes_fts WHERE id = ?", (node_id,))
            c.execute("INSERT INTO nodes_fts (id, type, name, content_text) VALUES (?,?,?,?)",
                      (node_id, type, name, fts_text))
            c.commit()
        return node_id

    def get_node(self, node_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
        if not row:
            return None
        return self._row_to_node(row)

    def find_nodes(self, type: str | None = None, name_contains: str | None = None,
                   limit: int = 50, offset: int = 0) -> list[dict]:
        q = "SELECT * FROM nodes WHERE 1=1"
        params: list = []
        if type:
            q += " AND type = ?"
            params.append(type)
        if name_contains:
            q += " AND name LIKE ?"
            params.append(f"%{name_contains}%")
        q += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        with self._conn() as c:
            rows = c.execute(q, params).fetchall()
        return [self._row_to_node(r) for r in rows]

    def all_nodes(self, types: list[str] | None = None) -> list[dict]:
        q = "SELECT id, type, name, meta, updated_at FROM nodes"
        params: list = []
        if types:
            ph = ",".join("?" * len(types))
            q += f" WHERE type IN ({ph})"
            params.extend(types)
        q += " ORDER BY updated_at DESC"
        with self._conn() as c:
            rows = c.execute(q, params).fetchall()
        return [{"id": r["id"], "type": r["type"], "name": r["name"],
                 "meta": json.loads(r["meta"] or "{}"),
                 "updated_at": r["updated_at"]} for r in rows]

    def delete_node(self, node_id: str) -> int:
        with self._conn() as c:
            n = c.execute("DELETE FROM nodes WHERE id = ?", (node_id,)).rowcount
            c.execute("DELETE FROM nodes_fts WHERE id = ?", (node_id,))
            c.execute("DELETE FROM edges WHERE src = ? OR dst = ?", (node_id, node_id))
            c.commit()
        return n

    # ── 엣지 ──────────────────────────────────────────────────────────

    def add_edge(self, src: str, dst: str, type: str,
                 weight: float = 1.0, meta: dict | None = None) -> int:
        if type not in EDGE_TYPES:
            raise ValueError(f"unknown edge type: {type}")
        meta_json = json.dumps(meta or {}, ensure_ascii=False)
        with self._conn() as c:
            cur = c.execute("""
                INSERT INTO edges (src, dst, type, weight, meta)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(src, dst, type) DO UPDATE SET
                    weight = edges.weight + excluded.weight,
                    meta = excluded.meta
            """, (src, dst, type, weight, meta_json))
            c.commit()
            return cur.lastrowid or 0

    def all_edges(self, types: list[str] | None = None) -> list[dict]:
        q = "SELECT id, src, dst, type, weight, meta FROM edges"
        params: list = []
        if types:
            ph = ",".join("?" * len(types))
            q += f" WHERE type IN ({ph})"
            params.extend(types)
        with self._conn() as c:
            rows = c.execute(q, params).fetchall()
        return [{"id": r["id"], "src": r["src"], "dst": r["dst"],
                 "type": r["type"], "weight": r["weight"],
                 "meta": json.loads(r["meta"] or "{}")} for r in rows]

    def neighbors(self, node_id: str, edge_type: str | None = None,
                  direction: str = "both") -> list[dict]:
        """direction: 'out' | 'in' | 'both' — 인접 노드 + 엣지 정보 반환."""
        out_q = "SELECT e.*, n.name as other_name, n.type as other_type FROM edges e " \
                "JOIN nodes n ON n.id = e.dst WHERE e.src = ?"
        in_q = "SELECT e.*, n.name as other_name, n.type as other_type FROM edges e " \
               "JOIN nodes n ON n.id = e.src WHERE e.dst = ?"
        params_o, params_i = [node_id], [node_id]
        if edge_type:
            out_q += " AND e.type = ?"
            in_q += " AND e.type = ?"
            params_o.append(edge_type)
            params_i.append(edge_type)
        results = []
        with self._conn() as c:
            if direction in ("out", "both"):
                for r in c.execute(out_q, params_o).fetchall():
                    results.append({
                        "edge_id": r["id"], "edge_type": r["type"], "weight": r["weight"],
                        "direction": "out",
                        "other": r["dst"], "other_name": r["other_name"],
                        "other_type": r["other_type"],
                    })
            if direction in ("in", "both"):
                for r in c.execute(in_q, params_i).fetchall():
                    results.append({
                        "edge_id": r["id"], "edge_type": r["type"], "weight": r["weight"],
                        "direction": "in",
                        "other": r["src"], "other_name": r["other_name"],
                        "other_type": r["other_type"],
                    })
        return results

    def backlinks(self, node_id: str) -> dict[str, list[dict]]:
        """들어오는 엣지를 type 별로 묶어 반환 — UI Backlinks 섹션 용."""
        groups: dict[str, list[dict]] = {}
        for n in self.neighbors(node_id, direction="in"):
            groups.setdefault(n["edge_type"], []).append(n)
        return groups

    def traverse(self, start: str, max_depth: int = 2,
                 edge_types: list[str] | None = None) -> dict[str, dict]:
        """BFS — start 에서 max_depth 까지 도달 가능한 노드와 거리.

        반환: {node_id: {"node": {...}, "distance": int, "via_edges": [...]}}
        """
        visited: dict[str, dict] = {}
        frontier = [(start, 0, [])]
        while frontier:
            cur_id, dist, path = frontier.pop(0)
            if cur_id in visited:
                continue
            node = self.get_node(cur_id)
            if not node:
                continue
            visited[cur_id] = {"node": node, "distance": dist, "via_edges": path}
            if dist >= max_depth:
                continue
            for n in self.neighbors(cur_id):
                if edge_types and n["edge_type"] not in edge_types:
                    continue
                frontier.append((n["other"], dist + 1, path + [n["edge_type"]]))
        return visited

    # ── 검색 ──────────────────────────────────────────────────────────

    def search_fts(self, query: str, type: str | None = None,
                   limit: int = 20) -> list[dict]:
        """FTS5 전문 검색 — name + content_text 매칭, BM25 기본 랭킹."""
        # FTS query 문법 escape (간단 버전)
        safe = query.replace('"', '""')
        q = "SELECT n.* FROM nodes_fts f JOIN nodes n ON n.id = f.id " \
            "WHERE nodes_fts MATCH ?"
        params: list = [f'"{safe}"']
        if type:
            q += " AND n.type = ?"
            params.append(type)
        q += " ORDER BY bm25(nodes_fts) LIMIT ?"
        params.append(limit)
        with self._conn() as c:
            rows = c.execute(q, params).fetchall()
        return [self._row_to_node(r) for r in rows]

    # ── 통계 ──────────────────────────────────────────────────────────

    def stats(self) -> dict:
        with self._conn() as c:
            type_counts = {}
            for r in c.execute("SELECT type, COUNT(*) as n FROM nodes GROUP BY type").fetchall():
                type_counts[r["type"]] = r["n"]
            edge_counts = {}
            for r in c.execute("SELECT type, COUNT(*) as n FROM edges GROUP BY type").fetchall():
                edge_counts[r["type"]] = r["n"]
            recent = c.execute(
                "SELECT id, type, name, updated_at FROM nodes "
                "ORDER BY updated_at DESC LIMIT 10"
            ).fetchall()
        return {
            "node_counts": type_counts,
            "edge_counts": edge_counts,
            "total_nodes": sum(type_counts.values()),
            "total_edges": sum(edge_counts.values()),
            "recent": [{"id": r["id"], "type": r["type"], "name": r["name"],
                        "updated_at": r["updated_at"]} for r in recent],
        }

    # ── 헬퍼 ──────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_node(row: sqlite3.Row) -> dict:
        return {
            "id": row["id"],
            "type": row["type"],
            "name": row["name"],
            "content": json.loads(row["content"] or "{}"),
            "meta": json.loads(row["meta"] or "{}"),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    @staticmethod
    def _extract_fts_text(name: str, content: dict) -> str:
        """노드 content 에서 검색 가능한 자연어 텍스트 추출."""
        parts = [name]
        if isinstance(content, dict):
            for key in ("description", "intent", "task_summary", "notes"):
                v = content.get(key)
                if isinstance(v, str):
                    parts.append(v)
            # reasoning 객체 (Playbook)
            r = content.get("reasoning") or {}
            if isinstance(r, dict):
                for k in ("task_decomposition", "why_this_approach"):
                    v = r.get(k)
                    if isinstance(v, str):
                        parts.append(v)
            # plan 의 thinking
            for step in (content.get("plan") or []):
                if isinstance(step, dict):
                    for k in ("intent", "thinking"):
                        v = step.get(k)
                        if isinstance(v, str):
                            parts.append(v)
        return "\n".join(parts)


# ── 싱글톤 헬퍼 ─────────────────────────────────────────────────────────
_default_graph: KnowledgeGraph | None = None


def get_graph(db_path: str = "") -> KnowledgeGraph:
    global _default_graph
    if _default_graph is None or db_path:
        _default_graph = KnowledgeGraph(db_path)
    return _default_graph
