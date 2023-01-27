import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesAdminCreateAdmin(unittest.TestCase):
    def admin_create_admin(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_create_admin(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    