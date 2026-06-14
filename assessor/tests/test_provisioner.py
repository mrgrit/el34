"""6v6 (옵션) provisioner — 순수 로직(템플릿/검증/파싱) 단위 테스트.

write/reload 는 docker+wazuh 통합이라 라이브로 검증(6v6.sh 사이클). 여기선 보안 핵심인
파라미터 화이트리스트 + 템플릿 렌더링 + sid 범위 + 파일 파싱만 stdlib 로 검증.

실행:  python3 -m unittest assessor.tests.test_provisioner -v
"""
from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET

from fastapi import HTTPException

from assessor import provisioner as P


class TemplateTest(unittest.TestCase):
    def test_command_template_renders_valid_xml(self):
        xml = P.TEMPLATES["alert_command_pattern"](110000, {"label": "m1", "pattern": "sqlmap", "level": 11})
        ET.fromstring("<root>" + xml + "</root>")          # well-formed
        self.assertIn('id="110000"', xml)
        self.assertIn('level="11"', xml)
        self.assertIn("<if_sid>100260</if_sid>", xml)       # cmdlog base 위
        self.assertIn("sqlmap", xml)

    def test_fim_template_renders_valid_xml(self):
        xml = P.TEMPLATES["alert_fim_path"](110001, {"label": "m2", "path_pattern": "/etc/nftables"})
        ET.fromstring("<root>" + xml + "</root>")
        self.assertIn("<if_group>syscheck</if_group>", xml)

    def test_level_clamped(self):
        xml = P.TEMPLATES["alert_command_pattern"](110000, {"label": "m", "pattern": "x", "level": 99})
        self.assertIn('level="15"', xml)                    # 1..15 로 clamp

    def test_wrap_sorts_and_groups(self):
        rules = {110001: '  <rule id="110001"></rule>\n', 110000: '  <rule id="110000"></rule>\n'}
        body = P._wrap(rules)
        self.assertLess(body.index("110000"), body.index("110001"))   # sid 정렬
        self.assertIn('<group name="6v6,provisioned,">', body)


class ValidationTest(unittest.TestCase):
    def test_label_reject(self):
        with self.assertRaises(HTTPException):
            P._v_label("bad<script>")
        self.assertEqual(P._v_label("mission-1 #2"), "mission-1 #2")

    def test_pattern_reject_angle_and_quote(self):
        for bad in ['a<b', 'a>b', 'a"b']:
            with self.assertRaises(HTTPException):
                P._v_pattern(bad)

    def test_pattern_accepts_pcre(self):
        self.assertEqual(P._v_pattern("rm\\s+-rf|/etc/shadow"), "rm\\s+-rf|/etc/shadow")


class SidTest(unittest.TestCase):
    def test_sid_range_constants(self):
        self.assertEqual(P.SID_BASE, 110000)        # 6자리(≤999999) — Wazuh rule id 제약
        self.assertLessEqual(P.SID_MAX, 999999)
        self.assertTrue(P.RULES_FILE.endswith("zz-6v6-provisioned-rules.xml"))  # 마지막 로드


if __name__ == "__main__":
    unittest.main(verbosity=2)
