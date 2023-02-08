import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesPotentiallyMaliciousFileShared(unittest.TestCase):
    def test_potentially_malicious_file_shared(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.potentially_malicious_file_shared(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_potentially_malicious_file_shared_title(self) -> None:
        rule = slack.rules.potentially_malicious_file_shared()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    