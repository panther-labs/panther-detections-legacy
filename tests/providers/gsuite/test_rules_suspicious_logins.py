import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesSuspiciousLogins(unittest.TestCase):
    def test_suspicious_logins(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.suspicious_logins(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    