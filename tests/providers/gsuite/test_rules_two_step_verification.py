import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesTwoStepVerification(unittest.TestCase):
    def test_two_step_verification(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.two_step_verification(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    