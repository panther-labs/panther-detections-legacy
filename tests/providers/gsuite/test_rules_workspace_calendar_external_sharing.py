import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceCalendarExternalSharing(unittest.TestCase):
    def test_workspace_calendar_external_sharing(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_calendar_external_sharing(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    