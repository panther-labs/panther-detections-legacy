import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesNewOwner(unittest.TestCase):
    def new_owner(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.new_owner(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    