import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesTestRulesNetworkScanning(unittest.TestCase):
    def network_scanning(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.network_scanning(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    