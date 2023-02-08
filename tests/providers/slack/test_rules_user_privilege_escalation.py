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
        evt = PantherEvent(json.loads(slack.sample_logs.user_privilege_escalation_role_changed_to_owner))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Slack User Made Owner")
    
    
    def test_user_privilege_escalation_severity(self) -> None:
        rule = slack.rules.user_privilege_escalation()
        evt = PantherEvent(json.loads(slack.sample_logs.user_privilege_escalation_permissions_assigned))
        sev = rule.severity.func(evt) #type: ignore

        self.assertEqual(sev, "Medium")        
        
    