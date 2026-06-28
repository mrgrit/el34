"""Harness Phase A 단위 테스트 — 파싱/검증/위상정렬 + mock 오케스트레이터.

LLM/실 인프라 불필요(execute_skill·_llm_chat·verifier 는 mock).
실행: PYTHONPATH=/opt/ccc-src:/opt/ccc-src/packages python3 -m unittest bastion.tests.test_harness
"""
from __future__ import annotations
import unittest

from bastion import harness as H
from bastion import orchestrator as O
from bastion.harness import HarnessSpec, Persona, Task, Verify, Phase


class TestParseValidate(unittest.TestCase):
    def test_manual_harnesses_valid(self):
        ids = [h["harness_id"] for h in H.list_harnesses()]
        self.assertIn("incident-response-team", ids)
        self.assertIn("threat-hunt-team", ids)
        for hid in ("incident-response-team", "threat-hunt-team"):
            spec = H.load_harness_from_dir(hid)
            self.assertTrue(spec.team, f"{hid}: empty team")
            self.assertTrue(spec.phases, f"{hid}: no phases")
            errs = H.validate_spec(spec)
            self.assertEqual(errs, [], f"{hid} validate: {errs}")

    def test_topo_order(self):
        spec = H.load_harness_from_dir("incident-response-team")
        batches = H.topo_batches(spec.all_tasks())
        flat = [t.task_id for b in batches for t in b]
        # triage 가 가장 먼저, report 가 가장 나중
        self.assertEqual(batches[0][0].task_id, "t-triage")
        self.assertEqual(flat[-1], "t-report")
        # 의존성: t-contain 은 t-hunt/t-timeline 이후
        self.assertGreater(flat.index("t-contain"), flat.index("t-hunt"))
        self.assertGreater(flat.index("t-contain"), flat.index("t-timeline"))

    def test_persona_tool_boundary(self):
        p = H.load_personas()["soc-lead"]
        self.assertFalse(p.can_write)           # 리더 무발화/읽기전용
        self.assertEqual(p.model_tier, "reasoning")
        red = H.load_personas()["red-team-operator"]
        self.assertEqual(red.model_tier, "attack")
        self.assertTrue(red.can_write)


class TestValidateNegative(unittest.TestCase):
    def _spec(self, tasks, team_roles):
        team = [Persona(role=r, allowed_skills=["shell"]) for r in team_roles]
        return HarnessSpec(harness_id="t", team=team,
                           phases=[Phase(id=0, tasks=tasks)])

    def test_self_verify_blocked(self):
        t = Task(task_id="a", persona="x",
                 verify=Verify(enabled=True, verifier_persona="x"))  # 검증자==생산자
        errs = H.validate_spec(self._spec([t], ["x"]))
        self.assertTrue(any("자기검증" in e or "verifier == producer" in e for e in errs))

    def test_cycle_detected(self):
        a = Task(task_id="a", persona="x", depends_on=["b"])
        b = Task(task_id="b", persona="x", depends_on=["a"])
        errs = H.validate_spec(self._spec([a, b], ["x"]))
        self.assertTrue(any("cyclic" in e for e in errs))

    def test_unknown_skill(self):
        team = [Persona(role="x", allowed_skills=["not_a_real_skill"])]
        spec = HarnessSpec(harness_id="t", team=team,
                           phases=[Phase(id=0, tasks=[Task(task_id="a", persona="x")])])
        errs = H.validate_spec(spec)
        self.assertTrue(any("allowed_skills not in SKILLS" in e for e in errs))

    def test_unknown_persona(self):
        t = Task(task_id="a", persona="ghost")
        errs = H.validate_spec(self._spec([t], ["x"]))
        self.assertTrue(any("unknown persona" in e for e in errs))


class _FakeEvidence:
    def add(self, **kw):
        pass


class _FakeExperience:
    def record(self, **kw):
        pass


class _FakeAgent:
    """orchestrator 가 쓰는 BastionAgent 표면만 흉내."""
    def __init__(self):
        self.ollama_url = "http://x"
        self.model = "m"
        self.vm_ips = {"bastion": "127.0.0.1"}
        self.session_id = "s-test"
        self._test_meta = {}
        self.evidence_db = _FakeEvidence()
        self.experience = _FakeExperience()

    def _enrich_params(self, name, args):
        return dict(args)

    def _assess_risk(self, name, params):
        return "low"

    def _should_ask_approval(self, risk, sk_def):
        return False

    def _pre_check(self, name, params):
        return True, ""


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        # LLM 호출 mock: tool_call 없이 즉시 최종 content 반환
        self._orig_llm = O._llm_chat
        O._llm_chat = lambda url, model, msgs, tools=None, num_predict=1200, temperature=0.2: \
            {"content": f"[mock 산출물 by {model}]", "tool_calls": []}
        # 검증 mock: 통과
        self._orig_verify = O.run_verifier
        O.run_verifier = lambda agent, verifier, task, produced, emit: {"passed": True, "reason": "mock-ok"}

    def tearDown(self):
        O._llm_chat = self._orig_llm
        O.run_verifier = self._orig_verify

    def test_run_harness_order_and_done(self):
        spec = H.load_harness_from_dir("incident-response-team")
        events = list(O.run_harness(spec, "테스트 인시던트", _FakeAgent(), approval_callback=lambda *a: True))
        kinds = [e["event"] for e in events]
        self.assertEqual(kinds[0], "harness_start")
        self.assertIn("harness_done", kinds)
        # task_done 순서: triage 가 contain/report 보다 먼저 완료
        done_order = [e["task_id"] for e in events if e["event"] == "task_done"]
        self.assertEqual(done_order[0], "t-triage")
        self.assertEqual(done_order[-1], "t-report")
        # 모든 태스크 done
        final = [e for e in events if e["event"] == "harness_done"][0]
        self.assertEqual(final["escalated"], [])
        self.assertTrue(all(t["status"] == "done" for t in final["tasks"]))

    def test_verify_escalation(self):
        # 강제 실패 verifier → escalate
        O.run_verifier = lambda agent, verifier, task, produced, emit: {"passed": False, "reason": "mock-fail"}
        spec = H.load_harness_from_dir("incident-response-team")
        events = list(O.run_harness(spec, "테스트", _FakeAgent(), approval_callback=lambda *a: True))
        esc = [e for e in events if e["event"] == "escalate"]
        self.assertTrue(esc, "verify 강제실패 시 escalate 이벤트가 있어야 함")
        final = [e for e in events if e["event"] == "harness_done"][0]
        self.assertTrue(final["escalated"], "escalated 목록 비어있으면 안 됨")


if __name__ == "__main__":
    unittest.main(verbosity=2)
