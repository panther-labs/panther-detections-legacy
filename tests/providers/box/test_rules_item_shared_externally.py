import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesItemSharedExternally(unittest.TestCase):
    def test_item_shared_externally(self) -> None:
        name_override = "Override Name"
        rule = box.rules.item_shared_externally(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    