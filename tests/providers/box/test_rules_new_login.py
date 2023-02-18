import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesNewLogin(unittest.TestCase):
    def test_new_login(self) -> None:
        name_override = "Override Name"
        rule = box.rules.new_login(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_new_login_title(self) -> None:
        rule = box.rules.new_login()
        evt = PantherEvent(json.loads(box.sample_logs.new_login_new_login_event))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [Bob Cat] logged in from a new device.")
    
    
    