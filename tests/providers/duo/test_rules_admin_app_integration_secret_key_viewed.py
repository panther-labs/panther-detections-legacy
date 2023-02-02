import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminAppIntegrationSecretKeyViewed(unittest.TestCase):
    def test_admin_app_integration_secret_key_viewed(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_app_integration_secret_key_viewed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    