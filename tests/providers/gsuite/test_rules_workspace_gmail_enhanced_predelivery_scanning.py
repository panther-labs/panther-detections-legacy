import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceGmailEnhancedPredeliveryScanning(unittest.TestCase):
    def test_workspace_gmail_enhanced_predelivery_scanning(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_gmail_enhanced_predelivery_scanning(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    