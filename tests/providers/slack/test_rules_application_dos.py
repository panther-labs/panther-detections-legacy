import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesApplicationDos(unittest.TestCase):
    def test_application_dos(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.application_dos(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
