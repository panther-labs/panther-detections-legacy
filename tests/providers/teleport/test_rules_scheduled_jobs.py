import unittest

from panther_sdk import detection
from panther_detections.providers import teleport


class TestRulesTestRulesScheduledJobs(unittest.TestCase):
    def test_scheduled_jobs(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.scheduled_jobs(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    