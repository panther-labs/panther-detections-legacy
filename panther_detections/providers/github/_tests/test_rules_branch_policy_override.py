import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesBranchPolicyOverride(unittest.TestCase):
    def test_branch_policy_override(self) -> None:
        name_override = "Override Name"
        rule = github.rules.branch_policy_override(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_branch_policy_override_title(self) -> None:
        rule = github.rules.branch_policy_override()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    