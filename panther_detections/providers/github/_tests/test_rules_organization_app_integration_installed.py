import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesOrganizationAppIntegrationInstalled(unittest.TestCase):
    def test_organization_app_integration_installed(self) -> None:
        name_override = "Override Name"
        rule = github.rules.organization_app_integration_installed(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_organization_app_integration_installed_title(self) -> None:
        rule = github.rules.organization_app_integration_installed()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    def test_organization_app_integration_installed_group_by(self) -> None:
        rule = github.rules.organization_app_integration_installed()
        test_evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))
        key = rule.alert_grouping.group_by(test_evt)

        #self.assertEqual(key, "DEDUP STRING")

    
    
    