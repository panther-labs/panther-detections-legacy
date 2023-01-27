import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesTestRulesAdminSsoSamlRequirementDisabled(unittest.TestCase):
    def admin_sso_saml_requirement_disabled(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.admin_sso_saml_requirement_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    