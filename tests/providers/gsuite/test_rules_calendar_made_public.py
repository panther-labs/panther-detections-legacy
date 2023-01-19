import unittest

from panther_sdk import detection
import panther_detections.providers.gsuite as gsuite 

print(gsuite.rules.calendar_made_public)


class TestRulesCalendarPublic(unittest.TestCase):
    def test_calendar_public(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.calendar_made_public(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)
