import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminMfaRestrictionsUpdated(unittest.TestCase):
    def test_admin_mfa_restrictions_updated(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_mfa_restrictions_updated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    