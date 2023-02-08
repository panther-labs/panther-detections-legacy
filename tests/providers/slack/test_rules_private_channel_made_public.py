import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesPrivateChannelMadePublic(unittest.TestCase):
    def test_private_channel_made_public(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.private_channel_made_public(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_private_channel_made_public_title(self) -> None:
        rule = slack.rules.private_channel_made_public()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    