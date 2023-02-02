import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminUserMfaBypassEnabled(unittest.TestCase):
    def test_admin_user_mfa_bypass_enabled(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_user_mfa_bypass_enabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    