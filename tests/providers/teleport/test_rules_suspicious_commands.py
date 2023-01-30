import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesSuspiciousCommands(unittest.TestCase):
    def test_suspicious_commands(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.suspicious_commands(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    