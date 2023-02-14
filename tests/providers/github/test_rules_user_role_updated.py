import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesUserRoleUpdated(unittest.TestCase):
    def test_user_role_updated(self) -> None:
        name_override = "Override Name"
        rule = github.rules.user_role_updated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_role_updated_title(self) -> None:
        rule = github.rules.user_role_updated()
        evt = PantherEvent(
            json.loads(github.sample_logs.user_role_updated_github___member_updated)
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title, "Org owner [cat] updated user's [bob] role ('admin' or 'member')"
        )
