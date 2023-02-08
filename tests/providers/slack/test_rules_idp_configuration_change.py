import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesIdpConfigurationChange(unittest.TestCase):
    def test_idp_configuration_change(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.idp_configuration_change(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_idp_configuration_change_title(self) -> None:
        rule = slack.rules.idp_configuration_change()
        evt = PantherEvent(json.loads(slack.sample_logs.idp_configuration_change_idp_configuration_added))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Slack IDP Configuration Added")
    
    
    