import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesPassthroughAnomaly(unittest.TestCase):
    def test_passthrough_anomaly(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.passthrough_anomaly(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
