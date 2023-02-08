import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesAppAccessExpanded(unittest.TestCase):
    def test_app_access_expanded(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.app_access_expanded(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_app_access_expanded_title(self) -> None:
        rule = slack.rules.app_access_expanded()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    def test_app_access_expanded_severity(self) -> None:
        rule = slack.rules.app_access_expanded()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))
        sev = rule.severity.func(evt)

        # self.assertEqual(sev, "Low")        
        
    