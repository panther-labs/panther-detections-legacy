import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import panther_audit


class TestRulesUserModified(unittest.TestCase):
    def test_user_modified(self) -> None:
        name_override = "Override Name"
        rule = panther_audit.rules.user_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_modified_title(self) -> None:
        rule = panther_audit.rules.user_modified()
        evt = PantherEvent(
            json.loads(panther_audit.sample_logs.user_modified_users_email_was_changed)
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "The user account user-email+anyplus@springfield.gov was modified by admin.email@springfield.gov",
        )
