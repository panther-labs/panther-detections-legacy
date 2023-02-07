import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import zendesk


class TestRulesUserRole(unittest.TestCase):
    def test_user_role(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.user_role(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_role_title(self) -> None:
        rule = zendesk.rules.user_role()
        evt = PantherEvent(json.loads(zendesk.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt)

        self.assertEqual(title, "Actor user [{event.udm('actor_user')}] changed [{event.udm('user')}] role from \
            {old_role} to {new_role}")
    
    
    