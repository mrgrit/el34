"""6v6 Assessor — /activity 모니터링 피드 단위 테스트 (stdlib unittest).

실행:  python3 -m unittest assessor.tests.test_activity -v   (repo 루트)
"""
from __future__ import annotations

import unittest

from assessor.activity import build_activity
from assessor.checks.base import ExecResult


class FakeExec:
    def exec(self, container, argv, timeout=15):
        if "pgrep" in argv:
            return ExecResult(0, "1 proc", "")
        return ExecResult(0, "7", "")


class FakeAlerts:
    def __init__(self, alerts):
        self._a = alerts

    def alerts(self, since_sec=None):
        return list(self._a)


def _cmd_prompt(ts, host, user, cmd, rc="0"):
    return {"timestamp": ts, "rule": {"id": "100260", "level": 3,
            "groups": ["6v6", "cmdlog", "audit"], "description": "cmd"},
            "agent": {"name": host},
            "data": {"cmd_user": user, "cmd_host": host, "command": cmd, "cmd_rc": rc}}


def _cmd_audit(ts, host, auid, cmd):
    return {"timestamp": ts, "rule": {"id": "80792", "level": 3,
            "groups": ["audit", "audit_command"], "description": "execve"},
            "agent": {"name": host},
            "data": {"audit": {"command": cmd, "exe": "/usr/bin/" + cmd, "auid": auid, "exit": "0"}}}


def _fim(ts, host, path, event="modified", who="root"):
    return {"timestamp": ts, "rule": {"id": "550", "level": 7, "groups": ["syscheck"],
            "description": "FIM"}, "agent": {"name": host},
            "syscheck": {"path": path, "event": event,
                         "audit": {"effective_user": {"name": who}}}}


def _alert(ts, rid, level, groups, desc, agent="fw"):
    return {"timestamp": ts, "rule": {"id": rid, "level": level, "groups": groups,
            "description": desc}, "agent": {"name": agent}}


SAMPLE = [
    _cmd_prompt("2026-06-03T12:00:00.000+0000", "attacker", "ccc", "sqlmap -u http://x"),
    _cmd_audit("2026-06-03T12:00:01.000+0000", "web", "1000", "nc"),
    _fim("2026-06-03T12:00:02.000+0000", "fw", "/etc/nftables.conf"),
    _alert("2026-06-03T12:00:03.000+0000", "100251", 6, ["haproxy", "web_attack", "attack"], "SQLi"),
    _alert("2026-06-03T12:00:04.000+0000", "5710", 5, ["authentication_failed"], "auth fail"),
]


class ActivityTest(unittest.TestCase):
    def _run(self, **req):
        return build_activity(req, FakeExec(), FakeAlerts(SAMPLE))

    def test_commands_both_sources(self):
        r = self._run(since_sec=10**9, want=["commands"])
        srcs = sorted(c["source"] for c in r["commands"])
        self.assertEqual(srcs, ["auditd", "prompt"])      # 두 소스 병합
        self.assertEqual(len(r["commands"]), 2)

    def test_fim(self):
        r = self._run(since_sec=10**9, want=["fim"])
        self.assertEqual(len(r["fim"]), 1)
        self.assertEqual(r["fim"][0]["path"], "/etc/nftables.conf")
        self.assertEqual(r["fim"][0]["action"], "modified")
        self.assertEqual(r["fim"][0]["who"], "root")

    def test_alerts_excludes_cmd_and_fim_and_noise(self):
        r = self._run(since_sec=10**9, want=["alerts"])
        ids = [a["rule_id"] for a in r["alerts"]]
        self.assertIn("100251", ids)         # web_attack → 포함
        self.assertNotIn("100260", ids)      # cmdlog → 제외
        self.assertNotIn("550", ids)         # syscheck → 제외
        self.assertNotIn("5710", ids)        # 보안그룹 아님 → 제외(기본)

    def test_alerts_groups_filter(self):
        r = self._run(since_sec=10**9, want=["alerts"], filter={"groups": "authentication_failed"})
        ids = [a["rule_id"] for a in r["alerts"]]
        self.assertEqual(ids, ["5710"])      # 명시 그룹 필터 시 해당만

    def test_filter_container(self):
        r = self._run(since_sec=10**9, want=["commands"], filter={"container": "web"})
        self.assertEqual(len(r["commands"]), 1)
        self.assertEqual(r["commands"][0]["source"], "auditd")

    def test_services_probe(self):
        r = self._run(since_sec=10**9, want=["services"])
        s = r["services"]
        self.assertEqual(s["apache"], "up")
        self.assertEqual(s["suricata"], "up")
        self.assertEqual(s["recent_apache_errors"], 7)

    def test_want_subset(self):
        r = self._run(since_sec=10**9, want=["fim"])
        self.assertIn("fim", r)
        self.assertNotIn("commands", r)
        self.assertNotIn("services", r)

    def test_limit(self):
        many = [_cmd_prompt(f"2026-06-03T12:00:{i:02d}.000+0000", "attacker", "ccc", f"cmd{i}")
                for i in range(30)]
        r = build_activity({"since_sec": 10**9, "want": ["commands"], "limit": 5},
                           FakeExec(), FakeAlerts(many))
        self.assertEqual(len(r["commands"]), 5)      # limit 적용


if __name__ == "__main__":
    unittest.main(verbosity=2)
