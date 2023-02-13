import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesOrgAuthModified(unittest.TestCase):
    def test_org_auth_modified(self) -> None:
        name_override = "Override Name"
        rule = github.rules.org_auth_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_org_auth_modified_title(self) -> None:
        rule = github.rules.org_auth_modified()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    