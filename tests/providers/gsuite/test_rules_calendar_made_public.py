import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesCalendarMadePublic(unittest.TestCase):
    def test_calendar_made_public(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.calendar_made_public(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    