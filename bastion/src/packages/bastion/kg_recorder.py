"""KG Recorder — bastion 결과를 structured anchor 로 KG 에 기록.

목표:
- agent 의 모든 stage transition (task 종료 / 발견 / asset 변화 / playbook 실행)
  결과를 structured schema (json) anchor 로 자동 누적.

설계:
- structured schema (schema_version 포함, 진화 대비)
- 자동 dedup (semantic hash key, 같은 (skills+mitre+outcome) 조합이면 1건)
- kind enum 강제 (오타 차단)
- 모든 호출 silent fallback (history.add_anchor 실패 시 None 반환)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any


SCHEMA_VERSION = 1

KIND_TASK_OUTCOME = "task_outcome"
KIND_OBSERVATION = "observation"
KIND_FINDING = "finding"
KIND_ASSET_STATE = "asset_state"
KIND_PLAYBOOK_EXEC = "playbook_exec"

_VALID_KINDS = {
    KIND_TASK_OUTCOME, KIND_OBSERVATION, KIND_FINDING,
    KIND_ASSET_STATE, KIND_PLAYBOOK_EXEC,
}

_MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def extract_mitre_ids(text: str) -> list[str]:
    if not text:
        return []
    return sorted(set(_MITRE_RE.findall(text)))


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _semantic_hash(*parts: Any) -> str:
    payload = json.dumps([str(p) for p in parts], ensure_ascii=False, sort_keys=True)
    return hashlib.sha1(payload.encode("utf-8", "ignore")).hexdigest()[:16]


class KGRecorder:
    def __init__(self, history=None, metrics=None):
        self._history = history
        self._metrics = metrics

    # ── Lazy ────────────────────────────────────────────────────────────────

    def _h(self):
        if self._history is False:
            return None
        if self._history is None:
            try:
                from packages.bastion.history import HistoryLayer
                self._history = HistoryLayer()
            except Exception:
                self._history = False
                return None
        return self._history

    # ── Public ──────────────────────────────────────────────────────────────

    def record_task_outcome(self, *, task_message: str,
                            skills_used: list[str],
                            mitre_ids: list[str],
                            success: bool,
                            score: float = 0.0,
                            evidence_excerpt: str = "",
                            source: str = "bastion-agent",
                            session_id: str = "",
                            asset_ids: list[str] | None = None) -> str | None:
        if not task_message:
            return None
        return self._record(
            kind=KIND_TASK_OUTCOME,
            label=f"task:{task_message[:80]}",
            body_doc={
                "schema_version": SCHEMA_VERSION,
                "task_message": task_message[:400],
                "skills_used": list(skills_used or []),
                "mitre_ids": list(mitre_ids or []),
                "outcome": {"success": bool(success), "score": float(score)},
                "evidence_excerpt": (evidence_excerpt or "")[:500],
                "source": source,
                "session_id": session_id,
                "asset_ids": list(asset_ids or []),
                "created_at": _now_iso(),
            },
            dedup_key=_semantic_hash(
                "task", task_message[:120],
                tuple(sorted(skills_used or [])),
                tuple(sorted(mitre_ids or [])),
                bool(success),
            ),
            related_ids=list(asset_ids or []) + list(mitre_ids or []),
        )

    def record_observation(self, *, asset_id: str,
                           observation_type: str,
                           evidence: str,
                           source: str = "bastion-agent") -> str | None:
        if not asset_id or not observation_type:
            return None
        return self._record(
            kind=KIND_OBSERVATION,
            label=f"obs:{asset_id}:{observation_type[:40]}",
            body_doc={
                "schema_version": SCHEMA_VERSION,
                "asset_id": asset_id,
                "observation_type": observation_type,
                "evidence": (evidence or "")[:600],
                "source": source,
                "created_at": _now_iso(),
            },
            dedup_key=_semantic_hash("obs", asset_id, observation_type,
                                     (evidence or "")[:120]),
            related_ids=[asset_id],
        )

    def record_finding(self, *, category: str,
                       severity: str,
                       evidence: str,
                       mitre_id: str = "",
                       suggested_action: str = "",
                       source: str = "bastion-agent") -> str | None:
        if not category:
            return None
        return self._record(
            kind=KIND_FINDING,
            label=f"finding:{category[:40]}:{mitre_id or 'na'}",
            body_doc={
                "schema_version": SCHEMA_VERSION,
                "category": category,
                "severity": severity,
                "mitre_id": mitre_id,
                "evidence": (evidence or "")[:600],
                "suggested_action": (suggested_action or "")[:300],
                "source": source,
                "created_at": _now_iso(),
            },
            dedup_key=_semantic_hash("finding", category, mitre_id, severity,
                                     (evidence or "")[:120]),
            related_ids=[mitre_id] if mitre_id else None,
        )

    def record_asset_state(self, *, asset_id: str,
                           state: str,
                           evidence: str = "",
                           source: str = "bastion-agent") -> str | None:
        if not asset_id or not state:
            return None
        return self._record(
            kind=KIND_ASSET_STATE,
            label=f"state:{asset_id}",
            body_doc={
                "schema_version": SCHEMA_VERSION,
                "asset_id": asset_id,
                "state": state,
                "evidence": (evidence or "")[:400],
                "source": source,
                "created_at": _now_iso(),
            },
            dedup_key=_semantic_hash("state", asset_id, state),
            related_ids=[asset_id],
        )

    def record_playbook_exec(self, *, playbook_id: str,
                             success: bool,
                             steps_total: int,
                             steps_passed: int,
                             elapsed_ms: int = 0,
                             source: str = "bastion-agent") -> str | None:
        if not playbook_id:
            return None
        return self._record(
            kind=KIND_PLAYBOOK_EXEC,
            label=f"pbexec:{playbook_id}",
            body_doc={
                "schema_version": SCHEMA_VERSION,
                "playbook_id": playbook_id,
                "success": bool(success),
                "steps_total": int(steps_total),
                "steps_passed": int(steps_passed),
                "elapsed_ms": int(elapsed_ms),
                "source": source,
                "created_at": _now_iso(),
            },
            dedup_key=_semantic_hash("pbexec", playbook_id, success, steps_total),
            related_ids=[playbook_id],
        )

    # ── Internal ────────────────────────────────────────────────────────────

    def _record(self, *, kind: str, label: str, body_doc: dict,
                dedup_key: str, related_ids: list[str] | None = None) -> str | None:
        if kind not in _VALID_KINDS:
            return None
        h = self._h()
        if h is None:
            return None
        try:
            if h.is_anchored(dedup_key):
                self._metric_inc("kg_record_dedup", labels={"kind": kind})
                return None

            body_doc["dedup_key"] = dedup_key
            body = json.dumps(body_doc, ensure_ascii=False)
            aid = h.add_anchor(kind, label, body, related_ids=related_ids or [])
            self._metric_inc("kg_record_total", labels={"kind": kind})
            return aid
        except Exception:
            self._metric_inc("kg_record_error", labels={"kind": kind})
            return None

    def _metric_inc(self, name: str, *, labels: dict | None = None):
        if not self._metrics:
            try:
                from packages.bastion.kg_metrics import get_metrics
                self._metrics = get_metrics()
            except Exception:
                return
        try:
            self._metrics.inc(name, labels=labels or {})
        except Exception:
            pass


_RECORDER: KGRecorder | None = None


def get_recorder() -> KGRecorder:
    global _RECORDER
    if _RECORDER is None:
        _RECORDER = KGRecorder()
    return _RECORDER
