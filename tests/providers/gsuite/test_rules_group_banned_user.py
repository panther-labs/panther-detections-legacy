import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesGroupBannedUser(unittest.TestCase):
    def test_group_banned_user(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.group_banned_user(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    