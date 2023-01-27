import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesAdminBypassCodeViewed(unittest.TestCase):
    def admin_bypass_code_viewed(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_bypass_code_viewed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    