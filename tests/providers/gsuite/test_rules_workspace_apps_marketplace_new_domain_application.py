import unittest

from panther_sdk import detection
from panther_detections.providers import google


class TestRulesWorkspaceAppsMarketplaceNewDomainApplication(unittest.TestCase):
    def test_workspace_apps_marketplace_new_domain_application(self) -> None:
        name_override = "Override Name"
        rule = google.rules.workspace_apps_marketplace_new_domain_application(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    