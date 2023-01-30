import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesUserPermissionUpdates(unittest.TestCase):
    def test_user_permission_updates(self) -> None:
        name_override = "Override Name"
        rule = box.rules.user_permission_updates(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    