import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import crowdstrike

class TestRulesDetectionPassthrough(unittest.TestCase):
    def test_detection_passthrough(self) -> None:
        name_override = "Override Name"
        rule = crowdstrike.rules.detection_passthrough(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)


    def test_detection_passthrough_group_by(self) -> None:
        rule = crowdstrike.rules.detection_passthrough()        
        test_evt = PantherEvent({"EventUUID": "333333", "ComputerName": "macbook"}, data_model=None)
        key = rule.alert_grouping.group_by(test_evt)  # type: ignore

        self.assertEqual(key, "333333 - macbook")

    def test_detection_passthrough_title(self) -> None:
        rule = crowdstrike.rules.detection_passthrough()
        evt = PantherEvent(json.loads(crowdstrike.sample_logs.low_severity_finding))

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "Crowdstrike Alert (PUP) - macbook(bobert)")

    def test_detection_passthrough_severity(self) -> None:
        rule = crowdstrike.rules.detection_passthrough()
        evt = PantherEvent(json.loads(crowdstrike.sample_logs.low_severity_finding))
        sev = rule.severity.func(evt)

        self.assertEqual(sev, "Low" )

