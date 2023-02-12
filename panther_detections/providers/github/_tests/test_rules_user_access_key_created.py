import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesUserAccessKeyCreated(unittest.TestCase):
    def test_user_access_key_created(self) -> None:
        name_override = "Override Name"
        rule = github.rules.user_access_key_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_access_key_created_title(self) -> None:
        rule = github.rules.user_access_key_created()
        evt = PantherEvent(json.loads(github.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    