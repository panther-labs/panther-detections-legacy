import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import panther_audit


class TestRulesSamlModified(unittest.TestCase):
    def test_saml_modified(self) -> None:
        name_override = "Override Name"
        rule = panther_audit.rules.saml_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_saml_modified_title(self) -> None:
        rule = panther_audit.rules.saml_modified()
        evt = PantherEvent(
            json.loads(panther_audit.sample_logs.saml_modified_saml_config_modified)
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title, "Panther SAML config has been modified by Homer Simpson"
        )
