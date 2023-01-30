import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesTestRulesSuspiciousCommands(unittest.TestCase):
    def suspicious_commands(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.suspicious_commands(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    