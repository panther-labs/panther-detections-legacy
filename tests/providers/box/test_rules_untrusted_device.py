import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesUntrustedDevice(unittest.TestCase):
    def test_untrusted_device(self) -> None:
        name_override = "Override Name"
        rule = box.rules.untrusted_device(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_untrusted_device_title(self) -> None:
        rule = box.rules.untrusted_device()
        evt = PantherEvent(json.loads(box.sample_logs.new_login_event))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [Bob Cat] attempted to login from an untrusted device.")
    
    
    