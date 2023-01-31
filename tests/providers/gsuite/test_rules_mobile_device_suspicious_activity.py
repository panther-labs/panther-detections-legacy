import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesMobileDeviceSuspiciousActivity(unittest.TestCase):
    def test_mobile_device_suspicious_activity(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.mobile_device_suspicious_activity(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    