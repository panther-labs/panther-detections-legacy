import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesUserSuspension(unittest.TestCase):
    def test_user_suspension(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.user_suspension(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_suspension_title(self) -> None:
        rule = zendesk.rules.user_suspension()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___suspension_enabled))

        title = rule.alert_title(evt)

        self.assertEqual(title, "Actor user [{event.udm('actor_user')}] {suspension_status} user [{user}]")
    
    
    def test_user_suspension_severity(self) -> None:
        rule = zendesk.rules.user_suspension()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___suspension_enabled))
        sev = rule.severity.func(evt)

        self.assertEqual(sev, "INFO")        
        
    