import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesAdminMarkedPushFraudulent(unittest.TestCase):
    def admin_marked_push_fraudulent(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_marked_push_fraudulent(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    