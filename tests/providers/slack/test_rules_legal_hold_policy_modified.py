import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesLegalHoldPolicyModified(unittest.TestCase):
    def test_legal_hold_policy_modified(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.legal_hold_policy_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_legal_hold_policy_modified_title(self) -> None:
        rule = slack.rules.legal_hold_policy_modified()
        evt = PantherEvent(json.loads(slack.sample_logs.legal_hold_policy_modified_legal_hold___exclusions_added))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Slack Exclusions Added to Legal Hold Policy")
    
    
    