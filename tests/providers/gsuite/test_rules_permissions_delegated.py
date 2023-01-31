import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesPermissionsDelegated(unittest.TestCase):
    def test_permissions_delegated(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.permissions_delegated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    