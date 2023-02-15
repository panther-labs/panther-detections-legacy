import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesAdminSsoSamlRequirementDisabled(unittest.TestCase):
    def test_admin_sso_saml_requirement_disabled(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_sso_saml_requirement_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_admin_sso_saml_requirement_disabled_title(self) -> None:
        rule = duo.rules.admin_sso_saml_requirement_disabled()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    