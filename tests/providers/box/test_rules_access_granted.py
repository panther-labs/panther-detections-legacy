import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesAccessGranted(unittest.TestCase):
    def test_access_granted(self) -> None:
        name_override = "Override Name"
        rule = box.rules.access_granted(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_access_granted_title(self) -> None:
        rule = box.rules.access_granted()
        evt = PantherEvent(json.loads(box.sample_logs.access_granted))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [Bob Cat]" \
            " granted access to their account")
    
    
    