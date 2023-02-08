import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import slack


class TestRulesOrgCreated(unittest.TestCase):
    def test_org_created(self) -> None:
        name_override = "Override Name"
        rule = slack.rules.org_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
