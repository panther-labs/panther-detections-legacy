import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesMfaSettingsChanged(unittest.TestCase):
    def test_mfa_settings_changed(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.mfa_settings_changed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
