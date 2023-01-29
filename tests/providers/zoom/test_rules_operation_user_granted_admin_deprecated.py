import unittest

from panther_sdk import detection
from panther_detections.providers import zoom


class TestRulesTestRulesOperationUserGrantedAdminDeprecated(unittest.TestCase):
    def operation_user_granted_admin_deprecated(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.operation_user_granted_admin_deprecated(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    