import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import box


class TestRulesMaliciousContent(unittest.TestCase):
    def test_malicious_content(self) -> None:
        name_override = "Override Name"
        rule = box.rules.malicious_content(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_malicious_content_title(self) -> None:
        rule = box.rules.malicious_content()
        evt = PantherEvent(json.loads(box.sample_logs.malicious_content))
        evt2 = PantherEvent(json.loads(box.sample_logs.file_marked_malicious))

        title = rule.alert_title(evt) #type: ignore
        title2 = rule.alert_title(evt2) #type: ignore

        self.assertEqual(title, "File [cat@example], owned by [malware.exe], was marked malicious.")
        self.assertEqual(title2, "File [bad_file.pdf], owned by [cat@example], was marked malicious.")
    
    
    