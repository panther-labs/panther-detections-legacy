import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceDataExportCreated(unittest.TestCase):
    def test_workspace_data_export_created(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_data_export_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    