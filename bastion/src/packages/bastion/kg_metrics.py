"""KG metrics — in-memory counter + histogram.

Prometheus-style. bastion API `/metrics` 에 노출 가능.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict


class KGMetrics:
    def __init__(self):
        self._lock = threading.Lock()
        self._counters: dict[tuple, int] = defaultdict(int)
        self._observations: dict[tuple, list[float]] = defaultdict(list)
        self._max_obs = 1000

    def inc(self, name: str, *, labels: dict | None = None):
        key = self._key(name, labels)
        with self._lock:
            self._counters[key] += 1

    def observe(self, name: str, value: float, *, labels: dict | None = None):
        key = self._key(name, labels)
        with self._lock:
            arr = self._observations[key]
            arr.append(float(value))
            if len(arr) > self._max_obs:
                del arr[: len(arr) - self._max_obs]

    def snapshot(self) -> dict:
        out: dict = {"counters": [], "observations": [], "ts": time.time()}
        with self._lock:
            for (name, labels_str), n in sorted(self._counters.items()):
                out["counters"].append({"name": name, "labels": labels_str, "value": n})
            for (name, labels_str), arr in sorted(self._observations.items()):
                if not arr:
                    continue
                a = sorted(arr)
                out["observations"].append({
                    "name": name,
                    "labels": labels_str,
                    "count": len(a),
                    "p50": a[len(a) // 2],
                    "p95": a[min(len(a) - 1, int(len(a) * 0.95))],
                    "max": a[-1],
                    "avg": sum(a) / len(a),
                })
        return out

    def reset(self):
        with self._lock:
            self._counters.clear()
            self._observations.clear()

    @staticmethod
    def _key(name: str, labels: dict | None) -> tuple:
        if not labels:
            return (name, "")
        items = sorted(labels.items())
        return (name, ",".join(f"{k}={v}" for k, v in items))


_METRICS: KGMetrics | None = None


def get_metrics() -> KGMetrics:
    global _METRICS
    if _METRICS is None:
        _METRICS = KGMetrics()
    return _METRICS
