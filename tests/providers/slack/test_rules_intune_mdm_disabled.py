import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesIntuneMdmDisabled(unittest.TestCase):
    def test_intune_mdm_disabled(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.intune_mdm_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
