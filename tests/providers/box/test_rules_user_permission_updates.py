import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesUserPermissionUpdates(unittest.TestCase):
    def test_user_permission_updates(self) -> None:
        name_override = "Override Name"
        rule = box.rules.user_permission_updates(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_permission_updates_title(self) -> None:
        rule = box.rules.user_permission_updates()
        evt = PantherEvent(json.loads(box.sample_logs.user_shares_item))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [cat@example] exceeded threshold for number " \
            "of permission changes in the configured time frame.")
    
    
    