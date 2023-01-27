import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesAdminNewAdminApiAppIntegration(unittest.TestCase):
    def admin_new_admin_api_app_integration(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_new_admin_api_app_integration(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    