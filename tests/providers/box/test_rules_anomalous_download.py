import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesAnomalousDownload(unittest.TestCase):
    def test_anomalous_download(self) -> None:
        name_override = "Override Name"
        rule = box.rules.anomalous_download(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    