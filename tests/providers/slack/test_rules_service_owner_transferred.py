import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesServiceOwnerTransferred(unittest.TestCase):
    def test_service_owner_transferred(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.service_owner_transferred(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_service_owner_transferred_title(self) -> None:
        rule = slack.rules.service_owner_transferred()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    