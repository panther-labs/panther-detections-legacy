import unittest
import json

from panther_detections.providers import crowdstrike
from panther_sdk import detection, PantherEvent


class TestRulesDnsRequest(unittest.TestCase):
    def test_dns_request(self) -> None:
        name_override = "Override Name"
        rule = crowdstrike.rules.dns_request(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_dns_request_group_by(self) -> None:
        rule = crowdstrike.rules.dns_request()

        test_evt = PantherEvent({"DomainName": "domain.com", "aid": "00000000000000000000000000000001"}, data_model=None)
        key = rule.alert_grouping.group_by(test_evt)  # type: ignore

        self.assertEqual(key, "domain.com-00000000000000000000000000000001")

    def test_dns_request_title(self) -> None:
        rule = crowdstrike.rules.dns_request()

        evt = PantherEvent(json.loads(crowdstrike.sample_logs.denylisted_domain))
        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "A denylisted domain [baddomain.com] was queried by host 00000000000000000000000000000001")
