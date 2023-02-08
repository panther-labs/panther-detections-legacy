import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import teleport


class TestRulesScheduledJobs(unittest.TestCase):
    def test_scheduled_jobs(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.scheduled_jobs(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_scheduled_jobs_title(self) -> None:
        rule = teleport.rules.scheduled_jobs()
        evt = PantherEvent(json.loads(teleport.sample_logs.crontab_no_args))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [panther] has modified scheduled jobs")
    
    
    