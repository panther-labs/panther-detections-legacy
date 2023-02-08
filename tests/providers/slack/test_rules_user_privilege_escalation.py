import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesUserPrivilegeEscalation(unittest.TestCase):
    def test_user_privilege_escalation(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.user_privilege_escalation(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_privilege_escalation_title(self) -> None:
        rule = slack.rules.user_privilege_escalation()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    def test_user_privilege_escalation_severity(self) -> None:
        rule = slack.rules.user_privilege_escalation()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))
        sev = rule.severity.func(evt)

        # self.assertEqual(sev, "Low")        
        
    