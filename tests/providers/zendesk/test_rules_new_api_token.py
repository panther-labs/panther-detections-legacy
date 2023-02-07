import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesNewApiToken(unittest.TestCase):
    def test_new_api_token(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.new_api_token(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_new_api_token_title(self) -> None:
        rule = zendesk.rules.new_api_token()
        evt = PantherEvent(json.loads(zendesk.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt)

        #self.assertEqual(title, "ADD TITLE")
    
    
    def test_new_api_token_severity(self) -> None:
        rule = zendesk.rules.new_api_token()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___api_token_created))
        sev = rule.severity.func(evt)

        self.assertEqual(sev, "HIGH")        
        
    