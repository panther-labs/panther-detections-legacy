import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesAdminBypassCodeCreated(unittest.TestCase):
    def test_admin_bypass_code_created(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_bypass_code_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    