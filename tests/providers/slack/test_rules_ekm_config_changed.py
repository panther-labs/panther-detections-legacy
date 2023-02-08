import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesEkmConfigChanged(unittest.TestCase):
    def test_ekm_config_changed(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.ekm_config_changed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_ekm_config_changed_title(self) -> None:
        rule = slack.rules.ekm_config_changed()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    