import unittest

from panther_sdk import detection
from panther_detections.providers import crowdstrike


class TestRulesRealTimeResponse(unittest.TestCase):
    def test_real_time_response(self) -> None:
        name_override = "Override Name"
        rule = crowdstrike.rules.real_time_response_session(
            overrides=detection.RuleOverrides(name=name_override)
        )

        # self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)
