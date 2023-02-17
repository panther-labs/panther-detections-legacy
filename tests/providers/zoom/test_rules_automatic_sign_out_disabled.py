import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zoom


class TestRulesAutomaticSignOutDisabled(unittest.TestCase):
    def test_automatic_sign_out_disabled(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.automatic_sign_out_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_automatic_sign_out_disabled_title(self) -> None:
        rule = zoom.rules.automatic_sign_out_disabled()
        evt = PantherEvent(json.loads(zoom.sample_logs.automatic_sign_out_disabled_automatic_signout_setting_disabled))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Zoom User [example@example.io] turned off your organization's setting to automatically sign users out after a specified time.")

