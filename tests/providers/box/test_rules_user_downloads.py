import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesUserDownloads(unittest.TestCase):
    def test_user_downloads(self) -> None:
        name_override = "Override Name"
        rule = box.rules.user_downloads(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    