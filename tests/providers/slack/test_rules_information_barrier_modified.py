import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesInformationBarrierModified(unittest.TestCase):
    def test_information_barrier_modified(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.information_barrier_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_information_barrier_modified_title(self) -> None:
        rule = slack.rules.information_barrier_modified()
        evt = PantherEvent(json.loads(slack.sample_logs.information_barrier_modified_information_barrier_deleted))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Slack Information Barrier Deleted")
    
    
    