import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesNewLogin(unittest.TestCase):
    def test_new_login(self) -> None:
        name_override = "Override Name"
        rule = box.rules.new_login(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    