import unittest
import json
from panther_sdk import detection, PantherEvent, schema
from panther_detections.providers import github


class TestRulesBranchPolicyOverride(unittest.TestCase):
    def test_branch_policy_override(self) -> None:
        name_override = "Override Name"
        rule = github.rules.branch_policy_override(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    # todo: test data model + fix error
    # panther_core.exceptions.PantherError: a data model hasn't been specified for log type: None

    def test_branch_policy_override_title(self) -> None:
        rule = github.rules.branch_policy_override()

        evt = PantherEvent(
            {"actor": "cat", "action": "protected_branch.policy_override"}
        )

        title = rule.alert_title(evt)

        self.assertEqual(
            title,
            "A branch protection requirement in the repository [<UNKNOWN_REPO>] was overridden by user [cat]",
        )
