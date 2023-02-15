import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import panther


class TestRulesUserModified(unittest.TestCase):
    def test_user_modified(self) -> None:
        name_override = "Override Name"
        rule = panther.rules.user_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_modified_title(self) -> None:
        rule = panther.rules.user_modified()
        evt = PantherEvent(json.loads(panther.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    