import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesUserRole(unittest.TestCase):
    def user_role(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.user_role(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    