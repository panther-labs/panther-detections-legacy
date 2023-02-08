import unittest

from panther_sdk import detection
from panther_detections.providers import duo


class TestRulesUserAnomalousPush(unittest.TestCase):
    def test_user_anomalous_push(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.user_anomalous_push(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    