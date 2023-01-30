import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesTestRulesCreateUserAccounts(unittest.TestCase):
    def create_user_accounts(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.create_user_accounts(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    