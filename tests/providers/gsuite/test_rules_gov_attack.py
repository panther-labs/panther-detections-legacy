import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesGovAttack(unittest.TestCase):
    def test_gov_attack(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.gov_attack(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    