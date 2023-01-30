import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesBruteForceLogin(unittest.TestCase):
    def test_brute_force_login(self) -> None:
        name_override = "Override Name"
        rule = box.rules.brute_force_login(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    