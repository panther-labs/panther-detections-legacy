import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesUserActionFraudulent(unittest.TestCase):
    def test_user_action_fraudulent(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.user_action_fraudulent(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    