import json
import unittest

from panther_sdk import detection, PantherEvent
from panther_detections.providers import onepassword


class TestRulesAdminActions(unittest.TestCase):
    def test_sensitive_item_access(self) -> None:
        name_override = "Override Name"
        rule = onepassword.rules.sensitive_item_access(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
