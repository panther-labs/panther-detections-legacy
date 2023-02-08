import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesBruteForceLogin(unittest.TestCase):
    def test_brute_force_login(self) -> None:
        name_override = "Override Name"
        rule = box.rules.brute_force_login(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_brute_force_login_title(self) -> None:
        rule = box.rules.brute_force_login()
        evt = PantherEvent(json.loads(box.sample_logs.login_failed))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [Bob Cat] has exceeded the failed login threshold.")
    
    
    