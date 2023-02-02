import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminPolicyUpdated(unittest.TestCase):
    def test_admin_policy_updated(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_policy_updated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    