"""PE-KG-H L4 — History layer.

기존 PE-KG (Playbook/Experience/Insight) 위에 시계열·내러티브·anchor·changelog
를 추가해 5년+ 운영의 컨텍스트 보존을 구조적으로 해결한다.

L4 핵심 노드:
- Event:     strict timestamp 의 atomic 사건 (Experience 의 단위 + 외부 사건)
- Narrative: 다수 Event 를 묶는 장기 흐름 (예: 2026-Q1 ransomware 캠페인 대응)
- Anchor:    압축 면역 플래그가 붙은 영구 보존 지식 (과거 침해 IoC, 규제 commitment)
- Changelog: 자산·룰·정책의 시간순 diff 체인

L4 핵심 엣지:
- precedes / follows : Event 간 시간 순서
- belongs_to         : Event → Narrative
- relates_to         : Anchor → Asset/Playbook (영구 참조)
- supersedes         : Changelog 차원 (룰 v2 가 v1 대체)

압축 정책: §4.5 의 3개 보존 게이트 (anchor 면역 / narrative atomic 보존 /
decision rationale 분리) 적용.
"""
from __future__ import annotations

import json
import sqlite3
import time
import uuid
from typing import Any, Iterable

from .graph import KnowledgeGraph, _resolve_db_path  # 기존 PE-KG 래퍼 재사용


# ── L4 추가 스키마 ──────────────────────────────────────────────────────────

L4_SCHEMA = """
-- 시계열 사건 — 모든 entry 는 strict timestamp 보유
CREATE TABLE IF NOT EXISTS history_events (
    id           TEXT PRIMARY KEY,
    ts           TEXT NOT NULL,           -- ISO 8601 (UTC), strict
    kind         TEXT NOT NULL,           -- task_done / policy_change / ioc_seen / handoff / decision / ...
    actor        TEXT DEFAULT '',         -- operator id 또는 'manager' / 'subagent:host'
    asset_id     TEXT DEFAULT '',         -- 관련 자산 (FK 느슨)
    narrative_id TEXT DEFAULT '',         -- 속한 narrative
    audit_seq    INTEGER DEFAULT 0,       -- §3.6 hash chain seq
    summary      TEXT NOT NULL,           -- 한 줄 요약
    payload      TEXT DEFAULT '{}'        -- JSON: 자세한 컨텍스트
);
CREATE INDEX IF NOT EXISTS idx_hev_ts        ON history_events(ts);
CREATE INDEX IF NOT EXISTS idx_hev_kind      ON history_events(kind);
CREATE INDEX IF NOT EXISTS idx_hev_asset     ON history_events(asset_id);
CREATE INDEX IF NOT EXISTS idx_hev_narrative ON history_events(narrative_id);

-- 장기 내러티브
CREATE TABLE IF NOT EXISTS history_narratives (
    id          TEXT PRIMARY KEY,
    title       TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    ended_at    TEXT,
    status      TEXT DEFAULT 'open',      -- open / closed
    summary     TEXT DEFAULT '',          -- narrative-level 요약 (압축 후도 유지)
    tags        TEXT DEFAULT '[]',
    meta        TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_nar_status ON history_narratives(status);

-- 압축 면역 anchor
CREATE TABLE IF NOT EXISTS history_anchors (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,            -- ioc / regulatory / policy_decision / breach_record
    label       TEXT NOT NULL,            -- 사람 가독 이름
    body        TEXT NOT NULL,            -- 영구 보존 본문 (verbatim)
    related_ids TEXT DEFAULT '[]',        -- ['asset:web', 'playbook:apt-phase1']
    created_at  TEXT DEFAULT (datetime('now')),
    valid_from  TEXT,
    valid_until TEXT,                     -- NULL = 영구
    immune      INTEGER DEFAULT 1         -- 1 = 압축 면역 (언제나 1, 명시 표시용)
);
CREATE INDEX IF NOT EXISTS idx_anc_kind  ON history_anchors(kind);
CREATE INDEX IF NOT EXISTS idx_anc_label ON history_anchors(label);

-- 자산·룰·정책 변경 체인
CREATE TABLE IF NOT EXISTS history_changelogs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target_kind TEXT NOT NULL,            -- asset / rule / policy / playbook
    target_id   TEXT NOT NULL,            -- 대상 식별자
    version     INTEGER NOT NULL,         -- 단조 증가
    ts          TEXT NOT NULL,
    actor       TEXT DEFAULT '',
    diff        TEXT NOT NULL,            -- 변경 내용 (textual diff 또는 JSON patch)
    rationale   TEXT DEFAULT '',          -- 변경 이유 (decision rationale)
    audit_seq   INTEGER DEFAULT 0,
    UNIQUE(target_kind, target_id, version)
);
CREATE INDEX IF NOT EXISTS idx_chg_target ON history_changelogs(target_kind, target_id);
CREATE INDEX IF NOT EXISTS idx_chg_ts     ON history_changelogs(ts);
"""


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


# ── L4 API ────────────────────────────────────────────────────────────────

class HistoryLayer:
    """L4 History 의 진입점. KnowledgeGraph 와 같은 SQLite DB 를 공유한다."""

    def __init__(self, db_path: str = ""):
        self.db_path = _resolve_db_path(db_path)
        self._init_schema()

    def _conn(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA foreign_keys = ON")
        return c

    def _init_schema(self) -> None:
        with self._conn() as c:
            for stmt in L4_SCHEMA.strip().split(";\n"):
                stmt = stmt.strip()
                if stmt:
                    c.execute(stmt)
            c.commit()

    # ── Event ────────────────────────────────────────────────────────────

    def add_event(self, kind: str, summary: str, *, actor: str = "",
                  asset_id: str = "", narrative_id: str = "",
                  audit_seq: int = 0, payload: dict | None = None,
                  ts: str | None = None) -> str:
        eid = f"evt-{uuid.uuid4().hex[:12]}"
        with self._conn() as c:
            c.execute(
                "INSERT INTO history_events "
                "(id, ts, kind, actor, asset_id, narrative_id, audit_seq, summary, payload) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (eid, ts or _now_iso(), kind, actor, asset_id, narrative_id,
                 audit_seq, summary, json.dumps(payload or {}, ensure_ascii=False)),
            )
            c.commit()
        return eid

    def list_events(self, *, asset_id: str = "", narrative_id: str = "",
                    kind: str = "", since: str = "", until: str = "",
                    limit: int = 100) -> list[dict]:
        q = "SELECT * FROM history_events WHERE 1=1"
        args: list[Any] = []
        if asset_id:
            q += " AND asset_id = ?"; args.append(asset_id)
        if narrative_id:
            q += " AND narrative_id = ?"; args.append(narrative_id)
        if kind:
            q += " AND kind = ?"; args.append(kind)
        if since:
            q += " AND ts >= ?"; args.append(since)
        if until:
            q += " AND ts <= ?"; args.append(until)
        q += " ORDER BY ts DESC LIMIT ?"; args.append(limit)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]

    # ── Narrative ────────────────────────────────────────────────────────

    def open_narrative(self, title: str, *, tags: list[str] | None = None,
                       summary: str = "", meta: dict | None = None) -> str:
        nid = f"nar-{uuid.uuid4().hex[:12]}"
        with self._conn() as c:
            c.execute(
                "INSERT INTO history_narratives "
                "(id, title, started_at, status, summary, tags, meta) "
                "VALUES (?,?,?, 'open', ?, ?, ?)",
                (nid, title, _now_iso(), summary,
                 json.dumps(tags or [], ensure_ascii=False),
                 json.dumps(meta or {}, ensure_ascii=False)),
            )
            c.commit()
        return nid

    def close_narrative(self, narrative_id: str, *, summary: str = "") -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE history_narratives SET status='closed', "
                "ended_at=?, summary=COALESCE(NULLIF(?, ''), summary) WHERE id=?",
                (_now_iso(), summary, narrative_id),
            )
            c.commit()

    def get_narrative(self, narrative_id: str) -> dict | None:
        with self._conn() as c:
            r = c.execute("SELECT * FROM history_narratives WHERE id=?",
                          (narrative_id,)).fetchone()
            return dict(r) if r else None

    # ── Anchor (압축 면역) ─────────────────────────────────────────────────

    def add_anchor(self, kind: str, label: str, body: str, *,
                   related_ids: list[str] | None = None,
                   valid_from: str = "", valid_until: str = "") -> str:
        aid = f"anc-{uuid.uuid4().hex[:12]}"
        with self._conn() as c:
            c.execute(
                "INSERT INTO history_anchors "
                "(id, kind, label, body, related_ids, valid_from, valid_until, immune) "
                "VALUES (?,?,?,?,?,?,?, 1)",
                (aid, kind, label, body,
                 json.dumps(related_ids or [], ensure_ascii=False),
                 valid_from or _now_iso(), valid_until or None),
            )
            c.commit()
        return aid

    def find_anchors(self, *, kind: str = "", label_like: str = "",
                     limit: int = 50) -> list[dict]:
        q = "SELECT * FROM history_anchors WHERE 1=1"
        args: list[Any] = []
        if kind:
            q += " AND kind = ?"; args.append(kind)
        if label_like:
            q += " AND label LIKE ?"; args.append(f"%{label_like}%")
        q += " ORDER BY created_at DESC LIMIT ?"; args.append(limit)
        with self._conn() as c:
            return [dict(r) for r in c.execute(q, args).fetchall()]

    def is_anchored(self, label_or_body: str) -> bool:
        """주어진 식별자(예: IoC IP/hash) 가 이미 anchor 로 등록되었는지."""
        with self._conn() as c:
            r = c.execute(
                "SELECT 1 FROM history_anchors WHERE label=? OR body LIKE ? LIMIT 1",
                (label_or_body, f"%{label_or_body}%"),
            ).fetchone()
        return r is not None

    # ── Changelog ────────────────────────────────────────────────────────

    def add_changelog(self, target_kind: str, target_id: str, diff: str, *,
                      actor: str = "", rationale: str = "",
                      audit_seq: int = 0) -> int:
        with self._conn() as c:
            r = c.execute(
                "SELECT COALESCE(MAX(version), 0) FROM history_changelogs "
                "WHERE target_kind=? AND target_id=?",
                (target_kind, target_id),
            ).fetchone()
            version = (r[0] if r else 0) + 1
            c.execute(
                "INSERT INTO history_changelogs "
                "(target_kind, target_id, version, ts, actor, diff, rationale, audit_seq) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (target_kind, target_id, version, _now_iso(), actor, diff,
                 rationale, audit_seq),
            )
            c.commit()
        return version

    def changelog(self, target_kind: str, target_id: str) -> list[dict]:
        with self._conn() as c:
            return [dict(r) for r in c.execute(
                "SELECT * FROM history_changelogs WHERE target_kind=? AND target_id=? "
                "ORDER BY version ASC",
                (target_kind, target_id),
            ).fetchall()]

    # ── 운영자용 핵심 쿼리 (논문 §4.6) ─────────────────────────────────────

    def handoff(self, asset_id: str, *, since: str = "") -> dict:
        """신규 운영자 인수인계 패키지 — 자산 별 narrative + anchor + 최근 changelog."""
        events = self.list_events(asset_id=asset_id, since=since, limit=200)
        narrative_ids = sorted({e["narrative_id"] for e in events if e.get("narrative_id")})
        narratives = []
        for nid in narrative_ids:
            n = self.get_narrative(nid)
            if n:
                narratives.append(n)
        anchors = self.find_anchors(label_like=asset_id, limit=50)
        return {
            "asset_id": asset_id,
            "since": since,
            "events": events,
            "narratives": narratives,
            "anchors": anchors,
            "changelog": self.changelog("asset", asset_id),
            "generated_at": _now_iso(),
        }

    def range_query(self, *, asset_id: str = "", since: str = "",
                    until: str = "") -> dict:
        """규제 감사용 시간 범위 쿼리."""
        return {
            "asset_id": asset_id,
            "since": since,
            "until": until,
            "events": self.list_events(asset_id=asset_id, since=since,
                                       until=until, limit=2000),
            "anchors_active": [
                a for a in self.find_anchors(label_like=asset_id, limit=200)
                if (not a.get("valid_until")) or a["valid_until"] >= since
            ],
            "generated_at": _now_iso(),
        }

    def match_repeat_iocs(self, observed: Iterable[str]) -> list[dict]:
        """신규 IoC 가 anchor 의 과거 침해 IoC 와 매칭되는지 조회."""
        hits = []
        with self._conn() as c:
            for ioc in observed:
                if not ioc:
                    continue
                rows = c.execute(
                    "SELECT id, kind, label, body, related_ids FROM history_anchors "
                    "WHERE kind='ioc' AND (label=? OR body LIKE ?) LIMIT 5",
                    (ioc, f"%{ioc}%"),
                ).fetchall()
                for r in rows:
                    hits.append({"ioc": ioc, **dict(r)})
        return hits


# ── Compaction 게이트 (§4.5) ──────────────────────────────────────────────

def is_compaction_immune(history: HistoryLayer, experience_id: str,
                         summary_text: str) -> bool:
    """Experience 압축 직전 호출. anchor 면역 / narrative 소속 / decision rationale
    중 하나라도 해당하면 True (= 압축에서 제외)."""
    # 1) summary 내 anchor 매칭
    if history.is_anchored(summary_text[:200]):
        return True
    # 2) experience 가 narrative 에 속하면 atomic 보존
    with history._conn() as c:
        r = c.execute(
            "SELECT 1 FROM history_events WHERE summary LIKE ? AND narrative_id != '' LIMIT 1",
            (f"%{experience_id}%",),
        ).fetchone()
        if r:
            return True
    return False


__all__ = [
    "HistoryLayer",
    "is_compaction_immune",
    "L4_SCHEMA",
]
