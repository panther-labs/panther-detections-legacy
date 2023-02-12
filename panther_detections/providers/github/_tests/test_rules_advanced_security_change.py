import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesAdvancedSecurityChange(unittest.TestCase):
    def test_advanced_security_change(self) -> None:
        name_override = "Override Name"
        rule = github.rules.advanced_security_change(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_advanced_security_change_title(self) -> None:
        rule = github.rules.advanced_security_change()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    def test_advanced_security_change_group_by(self) -> None:
        rule = github.rules.advanced_security_change()
        test_evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))
        key = rule.alert_grouping.group_by(test_evt)

        #self.assertEqual(key, "DEDUP STRING")

    
    
    def test_advanced_security_change_severity(self) -> None:
        rule = github.rules.advanced_security_change()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))
        sev = rule.severity.func(evt)

        # self.assertEqual(sev, "Low")        
        
    