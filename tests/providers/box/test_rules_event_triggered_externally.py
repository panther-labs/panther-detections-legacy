import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesEventTriggeredExternally(unittest.TestCase):
    def test_event_triggered_externally(self) -> None:
        name_override = "Override Name"
        rule = box.rules.event_triggered_externally(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_event_triggered_externally_title(self) -> None:
        rule = box.rules.event_triggered_externally()
        evt = PantherEvent(json.loads(box.sample_logs.previewed_anonymously))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "External user [<UNKNOWN_USER>] triggered a box event.")
    
    
    