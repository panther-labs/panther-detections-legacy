import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspacePasswordReuseEnabled(unittest.TestCase):
    def test_workspace_password_reuse_enabled(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_password_reuse_enabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    