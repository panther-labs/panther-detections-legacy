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
        evt = PantherEvent(json.loads(slack.sample_logs.app_access_expanded_app_scopes_expanded
))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Slack App [None] Access Expanded by [username]")
    
    
    def test_app_access_expanded_severity(self) -> None:
        rule = slack.rules.app_access_expanded()
        evt = PantherEvent(json.loads(slack.sample_logs.app_access_expanded_app_scopes_expanded))
        sev = rule.severity.func(evt) #type: ignore

        self.assertEqual(sev, "Medium")        
        
    