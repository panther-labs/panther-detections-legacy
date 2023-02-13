import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesBranchProtectionDisabled(unittest.TestCase):
    def test_branch_protection_disabled(self) -> None:
        name_override = "Override Name"
        rule = github.rules.branch_protection_disabled(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_branch_protection_disabled_title(self) -> None:
        rule = github.rules.branch_protection_disabled()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.branch_protection_disabled_github___branch_protection_disabled
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "A branch protection was removed from the repository [my-org/my-repo] by [cat]",
        )

    def test_branch_protection_disabled_alert_context(self) -> None:
        rule = github.rules.branch_protection_disabled()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.branch_protection_disabled_github___branch_protection_disabled
            )
        )

        alert_context_override = rule.alert_context(evt)  # type: ignore

        self.assertEqual(
            alert_context_override,
            {
                "action": "protected_branch.destroy",
                "actor": "cat",
                "actor_location": None,
                "org": "my-org",
                "repo": "my-org/my-repo",
                "user": "",
            },
        )
