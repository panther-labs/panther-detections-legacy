import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesUserEndpointFailureMulti(unittest.TestCase):
    def test_user_endpoint_failure_multi(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.user_endpoint_failure_multi(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    