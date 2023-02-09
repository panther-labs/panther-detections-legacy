import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceAdminCustomRole(unittest.TestCase):
    def test_workspace_admin_custom_role(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_admin_custom_role(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    