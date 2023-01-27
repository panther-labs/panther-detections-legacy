import unittest

from panther_sdk import detection
from panther_detections.providers import crowdstrike


class TestRulesDnsRequest(unittest.TestCase):
    def test_dns_request(self) -> None:
        name_override = "Override Name"
        rule = crowdstrike.rules.dns_request(
            overrides=detection.RuleOverrides(name=name_override)
        )


        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)
