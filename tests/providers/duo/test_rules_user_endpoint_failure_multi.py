import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import duo


class TestRulesUserEndpointFailureMulti(unittest.TestCase):
    def test_user_endpoint_failure_multi(self) -> None:
        name_override = "Override Name"
        rule = duo.rules.user_endpoint_failure_multi(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_user_endpoint_failure_multi_title(self) -> None:
        rule = duo.rules.user_endpoint_failure_multi()
        evt = PantherEvent(json.loads(duo.sample_logs.SAMPLEEVENT))

        title = rule.alert_title(evt) #type: ignore

        #self.assertEqual(title, "ADD TITLE")
    
    
    