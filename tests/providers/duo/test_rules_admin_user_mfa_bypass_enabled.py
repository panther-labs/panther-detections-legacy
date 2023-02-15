import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesAdminUserMfaBypassEnabled(unittest.TestCase):
    def test_admin_user_mfa_bypass_enabled(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_user_mfa_bypass_enabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_admin_user_mfa_bypass_enabled_title(self) -> None:
        rule = duo.rules.admin_user_mfa_bypass_enabled()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    