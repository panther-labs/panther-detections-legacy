import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zoom


class TestRulesAllMeetingsSecuredWithOneOptionDisabled(unittest.TestCase):
    def test_all_meetings_secured_with_one_option_disabled(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.all_meetings_secured_with_one_option_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_all_meetings_secured_with_one_option_disabled_title(self) -> None:
        rule = zoom.rules.all_meetings_secured_with_one_option_disabled()
        evt = PantherEvent(json.loads(zoom.sample_logs.all_meetings_secured_with_one_option_disabled_turn_off))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Zoom User [example@example.io] turned off your organization's requirement to secure all meetings with one security option.")
    
