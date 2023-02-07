import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesSensitiveDataRedaction(unittest.TestCase):
    def test_sensitive_data_redaction(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.sensitive_data_redaction(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_sensitive_data_redaction_title(self) -> None:
        rule = zendesk.rules.sensitive_data_redaction()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___credit_card_redaction_on))

        title = rule.alert_title(evt)

        self.assertEqual(title, "User [{event.udm('actor_user')}] {action} credit card redaction")
    
    
    def test_sensitive_data_redaction_severity(self) -> None:
        rule = zendesk.rules.sensitive_data_redaction()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___credit_card_redaction_on))
        sev = rule.severity.func(evt)

        self.assertEqual(sev, "INFO")        
        
    