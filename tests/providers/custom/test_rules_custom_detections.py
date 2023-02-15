import unittest
import json
from panther_sdk import detection, PantherEvent 
from panther_content.custom_detections import test_custom_title

class TestRulesBranchPolicyOverride(unittest.TestCase):
    def test_branch_policy_override_title(self) -> None:

        rule = test_custom_title()

        evt = PantherEvent(
            {
                "actor": "cat",
                "action": "protected_branch.policy_override",
                "num": 5,
                "p_log_type": "New.Log.Type",
            },
        )

        # print(datamodels.github_audit(evt))

        title = rule.alert_title(evt)

        self.assertEqual(
            title,
            "helloNew.Log.Type",
        )
