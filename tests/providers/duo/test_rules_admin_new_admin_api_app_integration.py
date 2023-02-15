import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesAdminNewAdminApiAppIntegration(unittest.TestCase):
    def test_admin_new_admin_api_app_integration(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_new_admin_api_app_integration(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_admin_new_admin_api_app_integration_title(self) -> None:
        rule = duo.rules.admin_new_admin_api_app_integration()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    