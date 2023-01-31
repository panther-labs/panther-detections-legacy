import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesGoogleAccess(unittest.TestCase):
    def test_google_access(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.google_access(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    