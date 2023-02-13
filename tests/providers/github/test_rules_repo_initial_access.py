import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesRepoInitialAccess(unittest.TestCase):
    def test_repo_initial_access(self) -> None:
        name_override = "Override Name"
        rule = github.rules.repo_initial_access(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_repo_initial_access_title(self) -> None:
        rule = github.rules.repo_initial_access()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    