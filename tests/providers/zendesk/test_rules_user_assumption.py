import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesUserAssumption(unittest.TestCase):
    def test_user_assumption(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.user_assumption(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_assumption_title(self) -> None:
        rule = zendesk.rules.user_assumption()
        evt = PantherEvent(json.loads(zendesk.sample_logs.user_assumption_settings_changed))

        title = rule.alert_title(evt)

        self.assertEqual(title, "A user [{event.udm('actor_user')}] updated zendesk support user assumption settings")
    
    
    