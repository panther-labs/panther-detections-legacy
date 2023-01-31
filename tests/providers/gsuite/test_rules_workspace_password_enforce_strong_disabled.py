import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspacePasswordEnforceStrongDisabled(unittest.TestCase):
    def test_workspace_password_enforce_strong_disabled(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_password_enforce_strong_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    