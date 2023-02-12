import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesPublicRepositoryCreated(unittest.TestCase):
    def test_public_repository_created(self) -> None:
        name_override = "Override Name"
        rule = github.rules.public_repository_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_public_repository_created_title(self) -> None:
        rule = github.rules.public_repository_created()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    def test_public_repository_created_group_by(self) -> None:
        rule = github.rules.public_repository_created()
        test_evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))
        key = rule.alert_grouping.group_by(test_evt)

        #self.assertEqual(key, "DEDUP STRING")

    
    
    