import unittest

from panther_sdk import detection
from panther_detections.providers import google


class TestRulesWorkspaceAppsMarketplaceAllowlist(unittest.TestCase):
    def test_workspace_apps_marketplace_allowlist(self) -> None:
        name_override = "Override Name"
        rule = google.rules.workspace_apps_marketplace_allowlist(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    