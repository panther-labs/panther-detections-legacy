import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesRepoCreated(unittest.TestCase):
    def test_repo_created(self) -> None:
        name_override = "Override Name"
        rule = github.rules.repo_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_repo_created_title(self) -> None:
        rule = github.rules.repo_created()
        evt = PantherEvent(json.loads(github.sample_logs.repo_created_github___repo_created))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "Repository [my-org/my-repo] created.")
    
    
    