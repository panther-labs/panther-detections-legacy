import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesNewApiToken(unittest.TestCase):
    def new_api_token(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.new_api_token(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    