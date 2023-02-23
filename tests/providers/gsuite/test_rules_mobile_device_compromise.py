import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesMobileDeviceCompromise(unittest.TestCase):
    def test_mobile_device_compromise(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.mobile_device_compromise(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    