import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import panther


class TestRulesSensitiveRoleCreated(unittest.TestCase):
    def test_sensitive_role_created(self) -> None:
        name_override = "Override Name"
        rule = panther.rules.sensitive_role_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_sensitive_role_created_title(self) -> None:
        rule = panther.rules.sensitive_role_created()
        evt = PantherEvent(json.loads(panther.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    