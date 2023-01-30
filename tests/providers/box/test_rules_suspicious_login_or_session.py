import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesSuspiciousLoginOrSession(unittest.TestCase):
    def test_suspicious_login_or_session(self) -> None:
        name_override = "Override Name"
        rule = box.rules.suspicious_login_or_session(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    