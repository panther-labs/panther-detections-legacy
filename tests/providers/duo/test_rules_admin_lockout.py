import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminLockout(unittest.TestCase):
    def test_admin_lockout(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_lockout(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    