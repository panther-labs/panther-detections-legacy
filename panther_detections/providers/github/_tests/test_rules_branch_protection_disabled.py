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
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    