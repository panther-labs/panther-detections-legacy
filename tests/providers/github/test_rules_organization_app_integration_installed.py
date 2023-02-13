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
        evt = PantherEvent(
            json.loads(
                github.sample_logs.organization_app_integration_installed_app_integration_installation
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "Github User [user_name] in [your-organization] installed"
            " the following integration: [Microsoft Teams for GitHub].",
        )
