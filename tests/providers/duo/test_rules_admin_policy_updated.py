import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesAdminPolicyUpdated(unittest.TestCase):
    def test_admin_policy_updated(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_policy_updated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_admin_policy_updated_title(self) -> None:
        rule = duo.rules.admin_policy_updated()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    