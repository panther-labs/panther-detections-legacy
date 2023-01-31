import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesDriveExternalShare(unittest.TestCase):
    def test_drive_external_share(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.drive_external_share(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    