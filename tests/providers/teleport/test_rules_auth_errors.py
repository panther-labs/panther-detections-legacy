import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesTestRulesAuthErrors(unittest.TestCase):
    def auth_errors(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.auth_errors(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    