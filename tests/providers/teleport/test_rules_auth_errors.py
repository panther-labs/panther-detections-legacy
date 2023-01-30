import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesAuthErrors(unittest.TestCase):
    def test_auth_errors(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.auth_errors(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
