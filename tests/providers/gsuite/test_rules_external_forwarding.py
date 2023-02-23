import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesExternalForwarding(unittest.TestCase):
    def test_external_forwarding(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.external_forwarding(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    