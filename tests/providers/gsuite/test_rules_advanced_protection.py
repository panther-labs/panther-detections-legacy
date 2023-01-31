import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesAdvancedProtection(unittest.TestCase):
    def test_advanced_protection(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.advanced_protection(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    