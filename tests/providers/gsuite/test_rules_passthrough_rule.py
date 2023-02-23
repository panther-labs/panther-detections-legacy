import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesPassthroughRule(unittest.TestCase):
    def test_passthrough_rule(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.passthrough_rule(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    