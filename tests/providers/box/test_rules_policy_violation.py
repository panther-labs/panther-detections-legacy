import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesPolicyViolation(unittest.TestCase):
    def test_policy_violation(self) -> None:
        name_override = "Override Name"
        rule = box.rules.policy_violation(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_policy_violation_title(self) -> None:
        rule = box.rules.policy_violation()
        evt = PantherEvent(json.loads(box.sample_logs.upload_policy_violation))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [Bob Cat] violated a content workflow policy.")
    
    
    