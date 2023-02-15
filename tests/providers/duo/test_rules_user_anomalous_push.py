import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesUserAnomalousPush(unittest.TestCase):
    def test_user_anomalous_push(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.user_anomalous_push(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_anomalous_push_title(self) -> None:
        rule = duo.rules.user_anomalous_push()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    