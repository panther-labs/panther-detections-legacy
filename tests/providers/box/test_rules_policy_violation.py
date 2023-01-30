import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesPolicyViolation(unittest.TestCase):
    def test_policy_violation(self) -> None:
        name_override = "Override Name"
        rule = box.rules.policy_violation(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    