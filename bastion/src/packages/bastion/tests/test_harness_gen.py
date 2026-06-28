"""Phase C 단위 테스트 — 하네스 자동 생성기(harness_gen).

discovery present 자산역할에 따라 페르소나가 선택되고, DAG 가 유효하며,
모델 자산(ai-model) 유무로 ai-security-analyst 가 포함/제외되는지 검증.
LLM 불필요(bind_playbooks=False, experience.get_context mock).
실행: PYTHONPATH=/opt/ccc-src:/opt/ccc-src/packages python3 -m unittest bastion.tests.test_harness_gen
"""
from __future__ import annotations
import unittest

from bastion import harness_gen as G
from bastion import harness as H


class _FakeExp:
    def get_context(self, msg):
        return ""


class _FakeAgent:
    def __init__(self):
        self.vm_ips = {"bastion": "127.0.0.1"}
        self.ollama_url = "http://x"
        self.model = "m"
        self.experience = _FakeExp()


def _gen(present):
    return G.generate_harness("테스트 SOC 요청", _FakeAgent(),
                              discovery_map={r: f"c-{r}" for r in present},
                              bind_playbooks=False, emit_artifacts=False)


class TestAutoGen(unittest.TestCase):
    def test_el34_like_valid_and_drops_ai(self):
        spec = _gen(["ids", "siem", "web", "fw", "attacker", "app", "portal"])
        roles = {p.role for p in spec.team}
        self.assertEqual(H.validate_spec(spec), [])
        # 인프라 매칭 페르소나 포함
        for r in ("soc-lead", "soc-triage-analyst", "threat-hunter", "siem-log-analyst",
                  "network-firewall-analyst", "detection-engineer", "incident-responder",
                  "vuln-asset-manager", "red-team-operator"):
            self.assertIn(r, roles, f"{r} 누락")
        # 모델 자산 없음 → ai-security-analyst 제외
        self.assertNotIn("ai-security-analyst", roles)
        # 보고가 마지막
        flat = [t.task_id for b in H.topo_batches(spec.all_tasks()) for t in b]
        self.assertEqual(flat[0], "t-triage")
        self.assertEqual(flat[-1], "t-report")
        self.assertEqual(spec.source, "auto")

    def test_ai_model_includes_ai_persona(self):
        spec = _gen(["siem", "web", "ai-model"])
        roles = {p.role for p in spec.team}
        self.assertIn("ai-security-analyst", roles)  # 모델 자산 있으면 포함
        self.assertEqual(H.validate_spec(spec), [])

    def test_no_fw_drops_network_and_contain(self):
        spec = _gen(["web"])   # fw/siem 없음
        roles = {p.role for p in spec.team}
        self.assertNotIn("network-firewall-analyst", roles)  # fw 없음
        self.assertNotIn("incident-responder", roles)        # fw/siem 없음
        self.assertEqual(H.validate_spec(spec), [])

    def test_minimal_present_still_valid(self):
        spec = _gen([])  # 아무 자산도 발견 못함
        roles = {p.role for p in spec.team}
        # 항상 포함되는 코어
        self.assertIn("soc-lead", roles)
        self.assertIn("soc-triage-analyst", roles)
        # 유효한 spec (triage + report 최소)
        self.assertEqual(H.validate_spec(spec), [])
        flat = [t.task_id for b in H.topo_batches(spec.all_tasks()) for t in b]
        self.assertEqual(flat[-1], "t-report")

    def test_verify_gates_on_write_tasks(self):
        spec = _gen(["ids", "siem", "web", "fw", "attacker"])
        vmap = {t.task_id: t for t in spec.all_tasks()}
        # 봉쇄/탐지 태스크에 verify 게이트 + 검증자=soc-lead(≠생산자)
        for tid in ("t-contain", "t-detect"):
            if tid in vmap:
                self.assertTrue(vmap[tid].verify.enabled)
                self.assertEqual(vmap[tid].verify.verifier_persona, "soc-lead")
                self.assertNotEqual(vmap[tid].persona, "soc-lead")


if __name__ == "__main__":
    unittest.main(verbosity=2)
