import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesLoginType(unittest.TestCase):
    def test_login_type(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.login_type(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    