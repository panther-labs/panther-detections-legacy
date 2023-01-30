import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesUntrustedDevice(unittest.TestCase):
    def test_untrusted_device(self) -> None:
        name_override = "Override Name"
        rule = box.rules.untrusted_device(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    