import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesAppRemoved(unittest.TestCase):
    def test_app_removed(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.app_removed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_app_removed_title(self) -> None:
        rule = slack.rules.app_removed()
        evt = PantherEvent(json.loads(slack.sample_logs.app_removed_app_uninstalled))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Slack App [app-name] Removed by [primary-owner]")
    
    
    