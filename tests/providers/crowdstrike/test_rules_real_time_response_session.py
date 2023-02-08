import unittest
import json

from panther_sdk import detection, PantherEvent
from panther_detections.providers import crowdstrike


class TestRulesRealTimeResponse(unittest.TestCase):
    def test_real_time_response(self) -> None:
        name_override = "Override Name"
        rule = crowdstrike.rules.real_time_response_session(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_real_time_response_title(self) -> None:
        rule = crowdstrike.rules.real_time_response_session()
        evt = PantherEvent(json.loads(crowdstrike.sample_logs.rts_session_start_event))
        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "example@example.io started a Crowdstrike Real-Time Response (RTR) shell on John Macbook Pro")

    def test_real_time_response_alert_context(self) -> None:
        rule = crowdstrike.rules.real_time_response_session()
        evt = PantherEvent(json.loads(crowdstrike.sample_logs.rts_session_start_event))
        context = rule.alert_context(evt)  # type: ignore
        
        self.assertEqual(context, {
            "Start Time": 1670460538,
            "SessionId": "6e1181e4-4924-4761-az3d-666851jdb950",
            "Actor": "example@example.io",
            "Target Host": "John Macbook Pro"
            })