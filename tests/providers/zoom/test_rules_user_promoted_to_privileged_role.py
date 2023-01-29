import unittest

from panther_sdk import detection
from panther_detections.providers import zoom


class TestRulesTestRulesUserPromotedToPrivilegedRole(unittest.TestCase):
    def user_promoted_to_privileged_role(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.user_promoted_to_privileged_role(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    