import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminCreateAdmin(unittest.TestCase):
    def test_admin_create_admin(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_create_admin(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    