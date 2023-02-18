import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesSuspiciousLoginOrSession(unittest.TestCase):
    def test_suspicious_login_or_session(self) -> None:
        name_override = "Override Name"
        rule = box.rules.suspicious_login_or_session(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_suspicious_login_or_session_title(self) -> None:
        rule = box.rules.suspicious_login_or_session()
        evt = PantherEvent(json.loads(box.sample_logs.suspicious_session_event))
        evt2 = PantherEvent(json.loads(box.sample_logs.suspicious_login_event))

        title = rule.alert_title(evt) #type: ignore
        title2 = rule.alert_title(evt2) #type: ignore

        self.assertEqual(title, "First time in prior month user connected from ip 1.2.3.4.")
        self.assertEqual(title2, "Shield medium to high risk, suspicious event alert triggered for user [bob@example]")
