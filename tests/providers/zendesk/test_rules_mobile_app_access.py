import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesMobileAppAccess(unittest.TestCase):
    def mobile_app_access(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.mobile_app_access(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    