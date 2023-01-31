import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesDriveVisibilityChangeDeprecated(unittest.TestCase):
    def test_drive_visibility_change_deprecated(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.drive_visibility_change_deprecated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    