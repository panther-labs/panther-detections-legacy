import json
import unittest

from panther_sdk import detection, PantherEvent
from panther_detections.providers import okta


class TestRulesAdminActions(unittest.TestCase):
    def test_admin_disabled_mfa(self) -> None:
        name_override = "Override Name"
        rule = okta.rules.admin_disabled_mfa(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_admin_role_assigned(self) -> None:
        name_override = "Override Name"
        rule = okta.rules.admin_role_assigned(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

        evt = PantherEvent(json.loads(okta.sample_logs.admin_access_assigned))

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "Jack Naglieri <jack@acme.io> granted [Organization administrator, Application administrator (all)] privileges to Alice Green <alice@acme.io>",
        )
