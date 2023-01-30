import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesEventTriggeredExternally(unittest.TestCase):
    def test_event_triggered_externally(self) -> None:
        name_override = "Override Name"
        rule = box.rules.event_triggered_externally(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    