import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesUserAssumption(unittest.TestCase):
    def user_assumption(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.user_assumption(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    