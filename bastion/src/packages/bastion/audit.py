"""Bastion Audit Log — 중요 시스템 작업 증적 로깅

설계 원칙:
  - Append-only (UPDATE/DELETE 금지 — 변조 시도 시 hash chain 으로 즉시 감지)
  - Hash chain (각 row 가 직전 row 의 hash 포함 → 한 줄 변경 시 이후 전부 깨짐)
  - 사용자 지시 원본 + 최종 답변 + 모든 의사결정 + 실행 흐름 전부 기록
  - 외부 SIEM 포워딩 가능 (선택)

저장 위치: bastion_audit.db (별도 파일 — 작업 DB 와 분리)

기록 단위: 1 chat = 1 row.
  request_id (uuid), session_id, user_id, source_ip, ts_start, ts_end
  user_prompt (전문), final_answer (전문)
  approval_mode, course/lab_id, verify_intent
  lookup: {decision, playbook_id, confidence, reason}
  turns: [{turn, content, thinking, tool_calls}]   # ReAct 전체 trace
  skill_calls: [{skill, params, risk, approved, success, exit_code, output_head, duration_ms}]
  judge: {pass, reason, criteria, keyword}    # test_step 외부 judge 가 전달한 경우
  outcome: success | partial | fail
  prev_hash, self_hash    # SHA-256 hash chain
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
import uuid


def _resolve_audit_db(db_path: str = "") -> str:
    if db_path:
        return db_path
    env = os.getenv("BASTION_AUDIT_DB", "").strip()
    if env:
        return env
    here = os.path.dirname(__file__)
    candidates = [
        os.path.normpath(os.path.join(here, "..", "..", "data", "bastion_audit.db")),
        os.path.normpath(os.path.join(here, "..", "data", "bastion_audit.db")),
    ]
    for c in candidates:
        d = os.path.dirname(c)
        if os.path.isdir(d) or os.access(os.path.dirname(d), os.W_OK):
            os.makedirs(d, exist_ok=True)
            return c
    return "/tmp/bastion_audit.db"


class AuditLog:
    """Append-only audit log with SHA-256 hash chain."""

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS audit (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id      TEXT NOT NULL UNIQUE,
        session_id      TEXT,
        user_id         TEXT,
        source_ip       TEXT,
        ts_start        TEXT NOT NULL,
        ts_end          TEXT,
        duration_ms     INTEGER,
        user_prompt     TEXT,
        final_answer    TEXT,
        approval_mode   TEXT,
        course          TEXT,
        lab_id          TEXT,
        step_order      INTEGER,
        verify_intent   TEXT,
        lookup_json     TEXT,            -- {decision, playbook_id, confidence, reason}
        turns_json      TEXT,            -- [{turn, content, thinking, tool_calls}]
        skill_calls_json TEXT,           -- [{skill, params, risk, approved, success, exit, output_head, ms}]
        judge_json      TEXT,            -- {pass, reason, criteria, keyword}
        outcome         TEXT,
        model_used      TEXT,
        bastion_version TEXT,
        test_meta_json  TEXT,
        prev_hash       TEXT,
        self_hash       TEXT NOT NULL,
        created_at      TEXT DEFAULT (datetime('now'))
    );
    CREATE INDEX IF NOT EXISTS idx_audit_session ON audit(session_id);
    CREATE INDEX IF NOT EXISTS idx_audit_user ON audit(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts_start);
    CREATE INDEX IF NOT EXISTS idx_audit_outcome ON audit(outcome);
    """

    def __init__(self, db_path: str = ""):
        self.db_path = _resolve_audit_db(db_path)
        self._init()

    def _conn(self):
        c = sqlite3.connect(self.db_path)
        c.row_factory = sqlite3.Row
        return c

    def _init(self):
        with self._conn() as c:
            for stmt in self.SCHEMA.strip().split(";\n"):
                if stmt.strip():
                    c.execute(stmt)
            c.commit()

    def _last_hash(self) -> str:
        with self._conn() as c:
            row = c.execute(
                "SELECT self_hash FROM audit ORDER BY id DESC LIMIT 1"
            ).fetchone()
        return row["self_hash"] if row else "GENESIS"

    @staticmethod
    def _canonical(payload: dict) -> str:
        """결정적 JSON — 같은 입력 = 같은 hash."""
        return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))

    def append(self, *,
               request_id: str = "",
               session_id: str = "",
               user_id: str = "",
               source_ip: str = "",
               ts_start: str = "",
               ts_end: str = "",
               duration_ms: int = 0,
               user_prompt: str = "",
               final_answer: str = "",
               approval_mode: str = "normal",
               course: str = "",
               lab_id: str = "",
               step_order: int = 0,
               verify_intent: str = "",
               lookup: dict | None = None,
               turns: list | None = None,
               skill_calls: list | None = None,
               judge: dict | None = None,
               outcome: str = "",
               model_used: str = "",
               bastion_version: str = "",
               test_meta: dict | None = None) -> dict:
        """1 chat 의 audit row 1개 append. 자동 hash chain.

        반환: {id, request_id, self_hash, prev_hash}
        """
        if not request_id:
            request_id = uuid.uuid4().hex
        if not ts_start:
            ts_start = time.strftime("%Y-%m-%dT%H:%M:%S")
        if not ts_end:
            ts_end = time.strftime("%Y-%m-%dT%H:%M:%S")
        prev_hash = self._last_hash()

        # hash 입력 — 모든 핵심 필드 포함
        payload = {
            "request_id": request_id,
            "session_id": session_id,
            "user_id": user_id,
            "source_ip": source_ip,
            "ts_start": ts_start,
            "ts_end": ts_end,
            "user_prompt": user_prompt,
            "final_answer": final_answer,
            "approval_mode": approval_mode,
            "course": course, "lab_id": lab_id, "step_order": step_order,
            "verify_intent": verify_intent,
            "lookup": lookup or {},
            "turns": turns or [],
            "skill_calls": skill_calls or [],
            "judge": judge or {},
            "outcome": outcome,
            "model_used": model_used,
            "bastion_version": bastion_version,
            "test_meta": test_meta or {},
            "prev_hash": prev_hash,
        }
        canonical = self._canonical(payload)
        self_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        with self._conn() as c:
            c.execute("""
                INSERT INTO audit (
                    request_id, session_id, user_id, source_ip,
                    ts_start, ts_end, duration_ms,
                    user_prompt, final_answer, approval_mode,
                    course, lab_id, step_order, verify_intent,
                    lookup_json, turns_json, skill_calls_json, judge_json,
                    outcome, model_used, bastion_version, test_meta_json,
                    prev_hash, self_hash
                ) VALUES (?,?,?,?, ?,?,?, ?,?,?, ?,?,?,?, ?,?,?,?, ?,?,?,?, ?,?)
            """, (
                request_id, session_id, user_id, source_ip,
                ts_start, ts_end, duration_ms,
                user_prompt, final_answer, approval_mode,
                course, lab_id, step_order, verify_intent,
                self._canonical(lookup or {}),
                self._canonical(turns or []),
                self._canonical(skill_calls or []),
                self._canonical(judge or {}),
                outcome, model_used, bastion_version,
                self._canonical(test_meta or {}),
                prev_hash, self_hash,
            ))
            row_id = c.execute("SELECT last_insert_rowid()").fetchone()[0]
            c.commit()

        # ── syslog forward → wazuh (UDP 직접, rsyslog 우회 — docker 환경에서 /dev/log 없음) ──
        # bastion-audit facility (local5) JSON 1줄. wazuh decoder 가 parse.
        # SIEM_HOST = wazuh manager (default 10.20.32.100:514/udp).
        try:
            import logging, logging.handlers, json as _json, os as _os
            global _BASTION_AUDIT_LOGGER
            if "_BASTION_AUDIT_LOGGER" not in globals():
                lg = logging.getLogger("bastion-audit")
                lg.setLevel(logging.INFO)
                siem_host = _os.environ.get("SIEM_HOST", "10.20.32.100")
                siem_port = int(_os.environ.get("SIEM_SYSLOG_PORT", "514"))
                # UDP 직접 송신 (rsyslog daemon 부재 환경 호환). 로컬 file fallback 도.
                try:
                    h = logging.handlers.SysLogHandler(address=(siem_host, siem_port),
                                                       facility=logging.handlers.SysLogHandler.LOG_LOCAL5,
                                                       socktype=__import__("socket").SOCK_DGRAM)
                    h.setFormatter(logging.Formatter("bastion-audit %(message)s"))
                    lg.addHandler(h)
                except Exception:
                    pass
                # 로컬 file 도 (Wazuh agent file watch + 디버그)
                try:
                    fh = logging.FileHandler("/var/log/bastion-audit.log")
                    fh.setFormatter(logging.Formatter("%(asctime)s bastion-audit %(message)s"))
                    lg.addHandler(fh)
                except Exception:
                    pass
                lg.propagate = False
                _BASTION_AUDIT_LOGGER = lg
            _BASTION_AUDIT_LOGGER.info(_json.dumps({
                "id": row_id, "request_id": request_id, "session_id": session_id,
                "ts_start": ts_start, "ts_end": ts_end, "duration_ms": duration_ms,
                "course": course, "lab_id": lab_id, "step_order": step_order,
                "user_prompt": (user_prompt or "")[:200],
                "outcome": outcome, "model": model_used,
                "self_hash": self_hash[:16],
            }, ensure_ascii=False))
        except Exception:
            pass  # syslog 실패 = DB 저장 영향 없음 (silent fail)

        return {"id": row_id, "request_id": request_id,
                "self_hash": self_hash, "prev_hash": prev_hash}

    def recent(self, limit: int = 50, **filters) -> list[dict]:
        """필터: session_id, user_id, course, outcome, since(ISO ts)."""
        q = "SELECT * FROM audit WHERE 1=1"
        params: list = []
        for key in ("session_id", "user_id", "course", "lab_id", "outcome"):
            if filters.get(key):
                q += f" AND {key} = ?"
                params.append(filters[key])
        if filters.get("since"):
            q += " AND ts_start >= ?"
            params.append(filters["since"])
        q += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as c:
            rows = c.execute(q, params).fetchall()
        return [dict(r) for r in rows]

    def get(self, request_id: str) -> dict | None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM audit WHERE request_id = ?",
                            (request_id,)).fetchone()
        return dict(row) if row else None

    def verify_chain(self, start_id: int = 1) -> dict:
        """hash chain 무결성 검증. tampering 있으면 깨진 첫 row id 반환."""
        with self._conn() as c:
            rows = c.execute(
                "SELECT * FROM audit WHERE id >= ? ORDER BY id ASC", (start_id,)
            ).fetchall()
        prev = "GENESIS" if start_id == 1 else None
        if start_id > 1:
            with self._conn() as c:
                pr = c.execute("SELECT self_hash FROM audit WHERE id = ?",
                               (start_id - 1,)).fetchone()
            prev = pr["self_hash"] if pr else "GENESIS"
        broken = []
        for r in rows:
            d = dict(r)
            payload = {
                "request_id": d["request_id"],
                "session_id": d["session_id"],
                "user_id": d["user_id"],
                "source_ip": d["source_ip"],
                "ts_start": d["ts_start"],
                "ts_end": d["ts_end"],
                "user_prompt": d["user_prompt"],
                "final_answer": d["final_answer"],
                "approval_mode": d["approval_mode"],
                "course": d["course"], "lab_id": d["lab_id"],
                "step_order": d["step_order"],
                "verify_intent": d["verify_intent"],
                "lookup": json.loads(d["lookup_json"] or "{}"),
                "turns": json.loads(d["turns_json"] or "[]"),
                "skill_calls": json.loads(d["skill_calls_json"] or "[]"),
                "judge": json.loads(d["judge_json"] or "{}"),
                "outcome": d["outcome"],
                "model_used": d["model_used"],
                "bastion_version": d["bastion_version"],
                "test_meta": json.loads(d["test_meta_json"] or "{}"),
                "prev_hash": d["prev_hash"],
            }
            canonical = self._canonical(payload)
            expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
            if expected != d["self_hash"]:
                broken.append({"id": d["id"], "request_id": d["request_id"],
                               "expected": expected, "actual": d["self_hash"]})
                break  # chain 깨짐 — 이후 전부 영향 받음
            if d["prev_hash"] != prev:
                broken.append({"id": d["id"], "request_id": d["request_id"],
                               "prev_mismatch": True,
                               "expected_prev": prev,
                               "actual_prev": d["prev_hash"]})
                break
            prev = d["self_hash"]
        return {"verified": len(rows), "broken": broken, "ok": not broken}

    def stats(self) -> dict:
        with self._conn() as c:
            total = c.execute("SELECT COUNT(*) as n FROM audit").fetchone()["n"]
            outcomes = {}
            for r in c.execute("SELECT outcome, COUNT(*) as n FROM audit "
                               "GROUP BY outcome").fetchall():
                outcomes[r["outcome"] or "unknown"] = r["n"]
            recent = c.execute(
                "SELECT request_id, ts_start, user_id, course, outcome "
                "FROM audit ORDER BY id DESC LIMIT 5"
            ).fetchall()
        return {"total": total, "outcomes": outcomes,
                "recent": [dict(r) for r in recent]}


# 싱글톤
_audit: AuditLog | None = None


def get_audit_log(db_path: str = "") -> AuditLog:
    global _audit
    if _audit is None or db_path:
        _audit = AuditLog(db_path)
    return _audit
