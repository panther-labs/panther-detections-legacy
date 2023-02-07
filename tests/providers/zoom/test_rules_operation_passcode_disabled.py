import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zoom


class TestRulesOperationPasscodeDisabled(unittest.TestCase):
    def test_operation_passcode_disabled(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.operation_passcode_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_operation_passcode_disabled_title(self) -> None:
        rule = zoom.rules.operation_passcode_disabled()
        evt = PantherEvent(json.loads(zoom.sample_logs.operation_passcode_disabled_meeting_passcode_disabled))

        title = rule.alert_title(evt)

        self.assertEqual(title, "Group Springfield passcode requirement disabled by homer@panther.io")
    
    
    