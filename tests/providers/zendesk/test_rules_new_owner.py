import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesNewOwner(unittest.TestCase):
    def test_new_owner(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.new_owner(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_new_owner_title(self) -> None:
        rule = zendesk.rules.new_owner()
        evt = PantherEvent(json.loads(zendesk.sample_logs.zendesk___owner_changed))

        title = rule.alert_title(evt)

        self.assertEqual(title, "zendesk administrative owner changed from Bob Cat to Mountain Lion")
