import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import panther_audit


class TestRulesSensitiveRoleCreated(unittest.TestCase):
    def test_sensitive_role_created(self) -> None:
        name_override = "Override Name"
        rule = panther_audit.rules.sensitive_role_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_sensitive_role_created_title(self) -> None:
        rule = panther_audit.rules.sensitive_role_created()
        evt = PantherEvent(
            json.loads(
                panther_audit.sample_logs.sensitive_role_created_admin_role_created
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "Role with Admin Permissions created by Homer SimpsonRole Name: New Admins",
        )
