import unittest

from panther_sdk import detection
from panther_detections.providers import zoom


class TestRulesTestRulesOperationPasscodeDisabled(unittest.TestCase):
    def operation_passcode_disabled(self) -> None:
        name_override = "Override Name"
        rule = zoom.rules.operation_passcode_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    