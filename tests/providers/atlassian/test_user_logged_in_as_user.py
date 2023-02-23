import json
import unittest

from panther_sdk import detection, PantherEvent
from panther_detections.providers import atlassian


class TestRulesAdminActions(unittest.TestCase):
    def test_user_logged_in_as_user(self) -> None:
        name_override = "Override Name"
        rule = atlassian.rules.user_logged_in_as_user(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)