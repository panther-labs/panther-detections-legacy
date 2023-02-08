import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesUserDownloads(unittest.TestCase):
    def test_user_downloads(self) -> None:
        name_override = "Override Name"
        rule = box.rules.user_downloads(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_downloads_title(self) -> None:
        rule = box.rules.user_downloads()
        evt = PantherEvent(json.loads(box.sample_logs.user_download))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [cat@example] exceeded threshold for number of downloads in the configured time frame.")
    
    
    