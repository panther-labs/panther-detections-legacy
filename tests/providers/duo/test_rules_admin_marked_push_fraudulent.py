import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminMarkedPushFraudulent(unittest.TestCase):
    def test_admin_marked_push_fraudulent(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_marked_push_fraudulent(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    