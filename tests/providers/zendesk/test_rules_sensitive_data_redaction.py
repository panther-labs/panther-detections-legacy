import unittest

from panther_sdk import detection
from panther_detections.providers import zendesk


class TestRulesTestRulesSensitiveDataRedaction(unittest.TestCase):
    def sensitive_data_redaction(self) -> None:
        name_override = "Override Name"
        rule = zendesk.rules.sensitive_data_redaction(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    