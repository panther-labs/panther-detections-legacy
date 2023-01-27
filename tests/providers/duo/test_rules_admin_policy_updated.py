import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesAdminPolicyUpdated(unittest.TestCase):
    def admin_policy_updated(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_policy_updated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    