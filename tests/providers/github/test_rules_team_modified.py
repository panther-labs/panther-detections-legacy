import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesTeamModified(unittest.TestCase):
    def test_team_modified(self) -> None:
        name_override = "Override Name"
        rule = github.rules.team_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_team_modified_title(self) -> None:
        rule = github.rules.team_modified()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    