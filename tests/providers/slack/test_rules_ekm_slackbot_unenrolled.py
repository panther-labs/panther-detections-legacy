import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesEkmSlackbotUnenrolled(unittest.TestCase):
    def test_ekm_slackbot_unenrolled(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.ekm_slackbot_unenrolled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_ekm_slackbot_unenrolled_title(self) -> None:
        rule = slack.rules.ekm_slackbot_unenrolled()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    