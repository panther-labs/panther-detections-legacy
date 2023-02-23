import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceGmailDefaultRoutingRule(unittest.TestCase):
    def test_workspace_gmail_default_routing_rule(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_gmail_default_routing_rule(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    