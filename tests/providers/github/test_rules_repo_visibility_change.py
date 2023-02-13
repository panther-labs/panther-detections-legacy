import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesRepoVisibilityChange(unittest.TestCase):
    def test_repo_visibility_change(self) -> None:
        name_override = "Override Name"
        rule = github.rules.repo_visibility_change(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_repo_visibility_change_title(self) -> None:
        rule = github.rules.repo_visibility_change()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    