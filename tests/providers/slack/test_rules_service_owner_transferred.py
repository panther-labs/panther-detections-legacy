import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesServiceOwnerTransferred(unittest.TestCase):
    def test_service_owner_transferred(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.service_owner_transferred(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    
    
    