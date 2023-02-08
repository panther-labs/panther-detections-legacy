import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box



class TestRulesAnomalousDownload(unittest.TestCase):
    def test_anomalous_download(self) -> None:
        name_override = "Override Name"
        rule = box.rules.anomalous_download(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    
    def test_anomalous_download_title(self) -> None:
        rule = box.rules.anomalous_download()
        evt = PantherEvent(json.loads(box.sample_logs.anomalous_download_event))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Significant increase in download content week over week," \
            " 9999% (50.00 MB) more than last week.")
    