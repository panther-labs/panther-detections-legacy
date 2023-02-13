import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github

# from panther_detections.datamodels import github_audit


class TestRulesOrgAuthModified(unittest.TestCase):
    def test_org_auth_modified(self) -> None:
        name_override = "Override Name"
        rule = github.rules.org_auth_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_org_auth_modified_title(self) -> None:
        rule = github.rules.org_auth_modified()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.org_auth_modified_github___authentication_method_changed
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "GitHub auth configuration was changed by cat")

    def test_branch_protection_disabled_alert_context(self) -> None:
        rule = github.rules.branch_protection_disabled()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.org_auth_modified_github___authentication_method_changed
            )
        )

        alert_context_override = rule.alert_context(evt)  # type: ignore

        self.assertEqual(
            alert_context_override,
            {
                "action": "org.saml_disabled",
                "actor": "cat",
                "actor_location": None,
                "org": "my-org",
                "repo": "my-org/my-repo",
                "user": "",
            },
        )
