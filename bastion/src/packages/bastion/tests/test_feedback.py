"""Phase D 단위 테스트 — 피드백 루프(성과 누적 → success_rate → 티어 조정/교훈 주입).

KG(BASTION_GRAPH_DB=temp)에 격리. 테스트 role 노드는 setUp 에서 정리.
실행: PYTHONPATH=/opt/ccc-src:/opt/ccc-src/packages BASTION_GRAPH_DB=/tmp/test_kg.db \
      python3 -m unittest bastion.tests.test_feedback
"""
from __future__ import annotations
import unittest

from bastion import feedback as F
from bastion.harness import Persona


def _del(role):
    try:
        from bastion.graph import get_graph
        get_graph().delete_node(f"persona:{role}")
    except Exception:
        pass


class TestFeedback(unittest.TestCase):
    ROLES = ["tf-rec", "tf-promo", "tf-demo", "tf-pit"]

    def setUp(self):
        for r in self.ROLES:
            _del(r)

    def tearDown(self):
        for r in self.ROLES:
            _del(r)

    def test_record_and_stats(self):
        for ok in [True, True, False, True]:
            F.record_persona_outcome("tf-rec", ok, reason="boom" if not ok else "")
        st = F.persona_stats("tf-rec")
        self.assertEqual(st["runs"], 4)
        self.assertAlmostEqual(st["success_rate"], 0.75, places=2)
        self.assertIn("boom", st["pitfalls"])

    def test_promote_readonly_proven(self):
        for _ in range(6):
            F.record_persona_outcome("tf-promo", True)
        p = Persona(role="tf-promo", model_tier="reasoning", can_write=False,
                    allowed_skills=["check_wazuh"])
        F.apply_feedback(p)
        self.assertEqual(p.model_tier, "execution")  # 검증된 읽기전용 → 경량화

    def test_demote_lowperf(self):
        for _ in range(3):
            F.record_persona_outcome("tf-demo", False, reason="fail")
        p = Persona(role="tf-demo", model_tier="execution", can_write=False,
                    allowed_skills=["check_wazuh"])
        F.apply_feedback(p)
        self.assertEqual(p.model_tier, "reasoning")        # 저성과 → 상향
        self.assertTrue(p.meta.get("force_verify"))         # verify 강제 플래그

    def test_pitfall_injection(self):
        F.record_persona_outcome("tf-pit", False, reason="차단 범위 과도")
        p = Persona(role="tf-pit", model_tier="reasoning", can_write=True,
                    allowed_skills=["configure_nftables"],
                    prompt={"quality_self_check": "기본 체크"})
        F.apply_feedback(p)
        self.assertIn("차단 범위 과도", p.prompt["quality_self_check"])

    def test_no_history_no_change(self):
        # 이력 없는 페르소나는 티어 불변(promote/demote 조건 미충족)
        p = Persona(role="tf-fresh-xyz", model_tier="reasoning", can_write=False,
                    allowed_skills=["check_wazuh"])
        F.apply_feedback(p)
        self.assertEqual(p.model_tier, "reasoning")


if __name__ == "__main__":
    unittest.main(verbosity=2)
