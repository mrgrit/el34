"""KG Context Builder — 모든 bastion LLM 호출의 표준 사전 참조.

목표:
- agent / planner / playbook runner / QA / Manager AI 등 모든 LLM 호출이
  자동으로 KG 검색 결과를 system prompt 에 받는다.

설계:
- tier-aware retrieval (Concept / Policy / Playbook / Asset / Anchor 분리)
- 모델별 token budget 동적 조정 (gemma 1500 / gpt-oss 4000 / default 1500)
- LRU cache (5분 TTL, message hash 기반)
- structured 출력 → format() 으로 markdown embed 형태 변환
- silent fallback (KG 호출 실패 시 빈 결과)
- 향후 embedding hybrid (sentence-transformers) 로 swap 가능한 interface
"""

from __future__ import annotations

import hashlib
import re
import time
from collections import OrderedDict
from typing import Any


_TOKEN_BUDGETS: dict[str, dict[str, int]] = {
    "gemma":   {"total": 1500, "anchor": 600,  "concept": 400,  "policy": 300, "playbook": 200, "asset": 200},
    "gpt-oss": {"total": 4000, "anchor": 1500, "concept": 1000, "policy": 800, "playbook": 700, "asset": 500},
    "default": {"total": 1500, "anchor": 600,  "concept": 400,  "policy": 300, "playbook": 200, "asset": 200},
}


def _budget_for(model: str) -> dict:
    if not model:
        return _TOKEN_BUDGETS["default"]
    m = model.lower()
    for prefix, budget in _TOKEN_BUDGETS.items():
        if prefix == "default":
            continue
        if prefix in m:
            return dict(budget)
    return dict(_TOKEN_BUDGETS["default"])


def _hash_key(message: str) -> str:
    return hashlib.sha1(
        (message or "").strip().lower().encode("utf-8", "ignore")
    ).hexdigest()[:16]


def _truncate(text: str, char_budget: int) -> str:
    if not text or len(text) <= char_budget:
        return text or ""
    return text[: max(1, char_budget - 3)] + "..."


def _chars_for_tokens(tokens: int) -> int:
    """한국어 평균 1 token ≈ 3 char (보수적)."""
    return max(0, tokens * 3)


_KEYWORD_SPLIT = re.compile(r"[\s,.\?\!\(\)\[\]\{\}<>:;\"\'/\\]+")


def _short_keywords(message: str, *, max_kws: int = 3) -> list[str]:
    """message 에서 검색용 짧은 키워드 추출 — anchor LIKE 검색 fallback."""
    if not message:
        return []
    parts = [p for p in _KEYWORD_SPLIT.split(message.strip()) if len(p) >= 3]
    seen: list[str] = []
    for p in parts:
        if p not in seen:
            seen.append(p)
        if len(seen) >= max_kws:
            break
    return seen


class KGContextBuilder:
    """모든 bastion LLM 호출의 표준 KG context.

    사용:
        b = get_builder()
        ctx = b.build(message, model="gemma3:4b")
        prompt_block = b.format(ctx)   # system prompt 에 삽입
    """

    _CACHE_TTL_SEC = 300
    _CACHE_MAX = 256

    def __init__(self, graph=None, history=None, metrics=None):
        self._graph_obj = graph
        self._history_obj = history
        self._metrics = metrics
        self._cache: OrderedDict[str, tuple[float, dict]] = OrderedDict()

    # ── Lazy lookup ─────────────────────────────────────────────────────────

    def _graph(self):
        if self._graph_obj is False:
            return None
        if self._graph_obj is None:
            try:
                from packages.bastion.graph import get_graph
                self._graph_obj = get_graph()
            except Exception:
                self._graph_obj = False
                return None
        return self._graph_obj

    def _history(self):
        if self._history_obj is False:
            return None
        if self._history_obj is None:
            try:
                from packages.bastion.history import HistoryLayer
                self._history_obj = HistoryLayer()
            except Exception:
                self._history_obj = False
                return None
        return self._history_obj

    # ── Public API ──────────────────────────────────────────────────────────

    def build(self, message: str, *, model: str = "",
              token_budget: dict | None = None) -> dict:
        """KG 검색 → structured dict.

        반환:
          {
            "concepts":  [{"id","name","summary"}, ...],
            "policies":  [...],
            "playbooks": [...],
            "assets":    [...],
            "anchors":   [{"id","kind","label","body"}, ...],
            "_metrics":  {"hits":N, "took_ms":...},
          }
        """
        if not message or not message.strip():
            return self._empty()

        budget = token_budget or _budget_for(model)
        key = _hash_key(message)

        # Cache hit
        cached = self._cache.get(key)
        if cached and time.time() - cached[0] < self._CACHE_TTL_SEC:
            self._cache.move_to_end(key)
            self._metric_inc("kg_context_cache_hit")
            cached_result = dict(cached[1])
            cached_result["_metrics"] = dict(cached_result.get("_metrics", {}))
            cached_result["_metrics"]["cache"] = "hit"
            return cached_result

        t0 = time.time()
        result: dict[str, Any] = {
            "concepts": [],
            "policies": [],
            "playbooks": [],
            "assets": [],
            "anchors": [],
            "_metrics": {},
        }

        graph = self._graph()
        if graph is not None:
            for tier_type, key_name in [
                ("Concept", "concepts"),
                ("Policy", "policies"),
                ("Playbook", "playbooks"),
                ("Asset", "assets"),
            ]:
                try:
                    nodes = graph.search_fts(message, type=tier_type, limit=3)
                except Exception:
                    nodes = []
                result[key_name] = [self._summarize_node(n) for n in nodes]

        history = self._history()
        if history is not None:
            anchors: list[dict] = []
            try:
                anchors = history.find_anchors(label_like=message[:60], limit=5)
            except Exception:
                anchors = []
            if not anchors:
                # short keyword fallback (T1190 / 'firewall' 등 단편)
                for kw in _short_keywords(message):
                    try:
                        more = history.find_anchors(label_like=kw, limit=3)
                    except Exception:
                        more = []
                    for a in more:
                        if a not in anchors:
                            anchors.append(a)
                    if len(anchors) >= 5:
                        break
            result["anchors"] = [self._summarize_anchor(a) for a in anchors[:5]]

        result = self._apply_budget(result, budget)

        took_ms = int((time.time() - t0) * 1000)
        result["_metrics"] = {
            "hits": sum(len(result[k]) for k in
                        ("concepts", "policies", "playbooks", "assets", "anchors")),
            "took_ms": took_ms,
            "cache": "miss",
        }

        self._metric_inc("kg_context_search", labels={"cache": "miss"})
        self._metric_observe("kg_context_search_took_ms", took_ms)

        self._cache_put(key, result)
        return result

    @staticmethod
    def format(result: dict, *, char_budget: int = 1500) -> str:
        """system prompt 에 embed 가능한 markdown 형태."""
        if not result:
            return ""
        sections: list[str] = []
        for field, header in [
            ("anchors", "Anchor (외부 지식 / 과거 결과)"),
            ("concepts", "Concept"),
            ("policies", "Policy"),
            ("playbooks", "Playbook"),
            ("assets", "Asset"),
        ]:
            items = result.get(field) or []
            if not items:
                continue
            block_lines = [f"## {header} ({len(items)}건)"]
            for it in items:
                ident = it.get("id", "?")
                if field == "anchors":
                    label = it.get("label") or "?"
                    body = it.get("body") or ""
                    block_lines.append(f"- [{ident}] {label} — {_truncate(body, 220)}")
                else:
                    name = it.get("name") or "?"
                    summary = it.get("summary") or ""
                    block_lines.append(f"- [{ident}] {name} — {_truncate(summary, 220)}")
            sections.append("\n".join(block_lines))

        if not sections:
            return ""
        full = ("# KG 컨텍스트 (사전 참조 — agent 는 이 정보를 활용해 plan/answer 보강)\n\n"
                + "\n\n".join(sections))
        return _truncate(full, char_budget)

    # ── Internal ────────────────────────────────────────────────────────────

    @staticmethod
    def _summarize_node(node: dict) -> dict:
        content = node.get("content") or {}
        if not isinstance(content, dict):
            content = {}
        summary: Any = (
            content.get("description")
            or content.get("summary")
            or content.get("intent")
            or content.get("body")
            or content.get("text")
            or ""
        )
        if isinstance(summary, (list, dict)):
            try:
                import json
                summary = json.dumps(summary, ensure_ascii=False)
            except Exception:
                summary = str(summary)
        return {
            "id": node.get("id", ""),
            "name": node.get("name", ""),
            "summary": str(summary)[:300],
        }

    @staticmethod
    def _summarize_anchor(a: dict) -> dict:
        return {
            "id": a.get("id", ""),
            "kind": a.get("kind", ""),
            "label": a.get("label", ""),
            "body": (a.get("body") or "")[:300],
        }

    def _apply_budget(self, result: dict, budget: dict) -> dict:
        """tier 별 char budget (token×3) 으로 truncate."""
        tier_to_field = {
            "anchor": "anchors",
            "concept": "concepts",
            "policy": "policies",
            "playbook": "playbooks",
            "asset": "assets",
        }
        for tier, field in tier_to_field.items():
            char_budget = _chars_for_tokens(budget.get(tier, 200))
            items = result.get(field) or []
            if not items:
                continue
            per_item = max(80, char_budget // max(1, len(items)))
            for it in items:
                if "summary" in it:
                    it["summary"] = _truncate(it["summary"], per_item)
                if "body" in it:
                    it["body"] = _truncate(it["body"], per_item)
        return result

    @staticmethod
    def _empty() -> dict:
        return {
            "concepts": [],
            "policies": [],
            "playbooks": [],
            "assets": [],
            "anchors": [],
            "_metrics": {"hits": 0, "took_ms": 0, "cache": "skip"},
        }

    def _cache_put(self, key: str, value: dict):
        self._cache[key] = (time.time(), value)
        self._cache.move_to_end(key)
        while len(self._cache) > self._CACHE_MAX:
            self._cache.popitem(last=False)

    # ── Metrics (silent) ────────────────────────────────────────────────────

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

    def _metric_observe(self, name: str, value: float, *, labels: dict | None = None):
        if not self._metrics:
            try:
                from packages.bastion.kg_metrics import get_metrics
                self._metrics = get_metrics()
            except Exception:
                return
        try:
            self._metrics.observe(name, value, labels=labels or {})
        except Exception:
            pass


_BUILDER: KGContextBuilder | None = None


def get_builder() -> KGContextBuilder:
    global _BUILDER
    if _BUILDER is None:
        _BUILDER = KGContextBuilder()
    return _BUILDER
