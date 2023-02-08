import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesMfaSettingsChanged(unittest.TestCase):
    def test_mfa_settings_changed(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.mfa_settings_changed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_mfa_settings_changed_title(self) -> None:
        rule = slack.rules.mfa_settings_changed()
        evt = PantherEvent(json.loads(slack.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    