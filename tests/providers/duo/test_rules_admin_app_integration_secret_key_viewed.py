import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesAdminAppIntegrationSecretKeyViewed(unittest.TestCase):
    def test_admin_app_integration_secret_key_viewed(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_app_integration_secret_key_viewed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_admin_app_integration_secret_key_viewed_title(self) -> None:
        rule = duo.rules.admin_app_integration_secret_key_viewed()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    