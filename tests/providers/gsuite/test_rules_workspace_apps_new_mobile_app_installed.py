import unittest

from panther_sdk import detection
from panther_detections.providers import google


class TestRulesWorkspaceAppsNewMobileAppInstalled(unittest.TestCase):
    def test_workspace_apps_new_mobile_app_installed(self) -> None:
        name_override = "Override Name"
        rule = google.rules.workspace_apps_new_mobile_app_installed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    