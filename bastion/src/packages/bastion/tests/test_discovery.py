"""Phase B 단위 테스트 — targets resolver(무회귀) + discovery 추론/파싱.

핵심: discovery 미적용 시 resolver 가 기존 el34 컨테이너 이름을 그대로 반환해야 한다
(무회귀). discovery 적용 시 발견된 이름으로 적응.
실행: PYTHONPATH=/opt/ccc-src:/opt/ccc-src/packages python3 -m unittest bastion.tests.test_discovery
"""
from __future__ import annotations
import os
import unittest

from bastion import targets
from bastion import discovery


class TestTargetsRegression(unittest.TestCase):
    """discovery off → 정적 el34 폴백 = 기존 동작 100% 동일."""

    def setUp(self):
        os.environ.pop("BASTION_DISCOVERY", None)
        discovery._DISCOVERED.clear()

    def test_static_fallback_el34(self):
        self.assertEqual(targets.container_for("attacker"), "el34-attacker")
        self.assertEqual(targets.container_for("ids"), "el34-ips")
        self.assertEqual(targets.container_for("siem"), "el34-siem")
        self.assertEqual(targets.container_for("web"), "el34-web")
        self.assertEqual(targets.container_for("fw"), "el34-fw")

    def test_wrap_docker_exec(self):
        et = targets.resolve_target("ids", {"bastion": "127.0.0.1"})
        ip, script = et.wrap("pgrep suricata")
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(script, 'docker exec el34-ips sh -c "pgrep suricata"')

    def test_unknown_role_fallback(self):
        # 미지 역할은 el34-<role> 로 폴백(정적 안전망)
        self.assertEqual(targets.container_for("portal"), "el34-portal")


class TestTargetsDiscovery(unittest.TestCase):
    """discovery on → 발견 매핑 사용. off 면 무시."""

    def tearDown(self):
        os.environ.pop("BASTION_DISCOVERY", None)
        discovery._DISCOVERED.clear()

    def test_discovered_used_when_enabled(self):
        discovery._DISCOVERED.update({"ids": "soc-suricata", "siem": "soc-wazuh"})
        os.environ["BASTION_DISCOVERY"] = "1"
        self.assertEqual(targets.container_for("ids"), "soc-suricata")
        self.assertEqual(targets.container_for("siem"), "soc-wazuh")
        # 발견 안 된 역할은 정적 폴백
        self.assertEqual(targets.container_for("fw"), "el34-fw")

    def test_discovered_ignored_when_disabled(self):
        discovery._DISCOVERED.update({"ids": "soc-suricata"})
        os.environ.pop("BASTION_DISCOVERY", None)
        self.assertEqual(targets.container_for("ids"), "el34-ips")  # 정적


class TestInferRole(unittest.TestCase):
    def test_el34_names(self):
        cases = {
            "el34-ips": "ids", "el34-siem": "siem", "el34-web": "web",
            "el34-fw": "fw", "el34-attacker": "attacker",
            "el34-wazuh-indexer": "indexer", "el34-wazuh-dashboard": "dashboard",
            "el34-portal": "portal",
        }
        for name, expected in cases.items():
            self.assertEqual(discovery.infer_role(name, name), expected,
                             f"{name} → {expected}")

    def test_image_based(self):
        self.assertEqual(discovery.infer_role("c1", "owasp/modsecurity-crs"), "web")
        self.assertEqual(discovery.infer_role("x", "ollama/ollama"), "ai-model")

    def test_unknown(self):
        self.assertIsNone(discovery.infer_role("random-thing", "alpine"))


class TestDiscoverInfra(unittest.TestCase):
    def setUp(self):
        self._orig = discovery.run_command
        fake_ps = ("el34-ips|el34-ips|Up 1h|\n"
                   "el34-siem|el34-siem:custom|Up 1h (healthy)|\n"
                   "el34-web|el34-web|Up 1h|0.0.0.0:80->80/tcp\n"
                   "el34-fw|el34-fw|Up 1h|\n"
                   "el34-attacker|el34-attacker|Up 1h|\n"
                   "el34-wazuh-indexer|wazuh/wazuh-indexer|Up 1h|\n")
        discovery.run_command = lambda ip, script, timeout=20: {"stdout": fake_ps, "exit_code": 0}

    def tearDown(self):
        discovery.run_command = self._orig
        discovery._DISCOVERED.clear()

    def test_role_map_built(self):
        d = discovery.discover_infra({"bastion": "127.0.0.1"}, register_assets=False)
        self.assertEqual(d["count"], 6)
        rm = d["role_map"]
        self.assertEqual(rm.get("ids"), "el34-ips")
        self.assertEqual(rm.get("siem"), "el34-siem")
        self.assertEqual(rm.get("web"), "el34-web")
        self.assertEqual(rm.get("fw"), "el34-fw")
        self.assertEqual(rm.get("attacker"), "el34-attacker")
        self.assertEqual(rm.get("indexer"), "el34-wazuh-indexer")
        # 발견 후 캐시 조회
        self.assertEqual(discovery.get_discovered_container("ids"), "el34-ips")


if __name__ == "__main__":
    unittest.main(verbosity=2)
