import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesLeakedPassword(unittest.TestCase):
    def test_leaked_password(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.leaked_password(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    