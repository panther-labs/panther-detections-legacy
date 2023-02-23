import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesUserSuspended(unittest.TestCase):
    def test_user_suspended(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.user_suspended(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    