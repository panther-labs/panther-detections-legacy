import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceGmailSecuritySandboxDisabled(unittest.TestCase):
    def test_workspace_gmail_security_sandbox_disabled(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_gmail_security_sandbox_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    