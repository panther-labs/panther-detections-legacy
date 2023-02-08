import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import teleport


class TestRulesAuthErrors(unittest.TestCase):
    def test_auth_errors(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.auth_errors(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_auth_errors_title(self) -> None:
        rule = teleport.rules.auth_errors()
        evt = PantherEvent(json.loads(teleport.sample_logs.ssh_errors))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "A high volume of SSH errors was detected from user [panther]")
    
    
    