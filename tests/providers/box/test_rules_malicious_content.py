import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesMaliciousContent(unittest.TestCase):
    def test_malicious_content(self) -> None:
        name_override = "Override Name"
        rule = box.rules.malicious_content(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    