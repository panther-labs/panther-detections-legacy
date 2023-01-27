import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesUserBypassCodeUsed(unittest.TestCase):
    def user_bypass_code_used(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.user_bypass_code_used(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    