import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesMobileAppAccess(unittest.TestCase):
    def test_mobile_app_access(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.mobile_app_access(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_mobile_app_access_title(self) -> None:
        rule = zendesk.rules.mobile_app_access()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___mobile_app_access_off))

        title = rule.alert_title(evt)

        self.assertEqual(title, "User [123] create mobile app access")
    
    
    def test_mobile_app_access_severity(self) -> None:
        rule = zendesk.rules.mobile_app_access()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___mobile_app_access_on))
        sev = rule.severity.func(evt)

        self.assertEqual(sev, "MEDIUM")        
        
    