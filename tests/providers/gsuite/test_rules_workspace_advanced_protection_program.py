import unittest

from panther_sdk import detection
from panther_detections.providers import google


class TestRulesWorkspaceAdvancedProtectionProgram(unittest.TestCase):
    def test_workspace_advanced_protection_program(self) -> None:
        name_override = "Override Name"
        rule = google.rules.workspace_advanced_protection_program(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    