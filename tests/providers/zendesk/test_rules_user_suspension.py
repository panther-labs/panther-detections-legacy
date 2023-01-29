import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesUserSuspension(unittest.TestCase):
    def user_suspension(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.user_suspension(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    