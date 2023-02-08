import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesEkmSlackbotUnenrolled(unittest.TestCase):
    def test_ekm_slackbot_unenrolled(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.ekm_slackbot_unenrolled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
