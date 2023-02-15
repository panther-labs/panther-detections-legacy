import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesItemSharedExternally(unittest.TestCase):
    def test_item_shared_externally(self) -> None:
        name_override = "Override Name"
        rule = box.rules.item_shared_externally(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_item_shared_externally_title(self) -> None:
        rule = box.rules.item_shared_externally()
        evt = PantherEvent(json.loads(box.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] shared an item [{deep_get(event, 'source', 'item_name', default='<UNKNOWN_NAME>')}] externally.")
    
    
    