import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import panther_audit


class TestRulesDetectionDeleted(unittest.TestCase):
    def test_detection_deleted(self) -> None:
        name_override = "Override Name"
        rule = panther_audit.rules.detection_deleted(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_detection_deleted_title(self) -> None:
        rule = panther_audit.rules.detection_deleted()
        evt = PantherEvent(
            json.loads(panther_audit.sample_logs.detection_deleted_delete_1_detection)
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "Detection Content has been deleted by Homer Simpson")
