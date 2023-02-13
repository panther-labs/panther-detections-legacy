import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesOrgIpAllowlist(unittest.TestCase):
    def test_org_ip_allowlist(self) -> None:
        name_override = "Override Name"
        rule = github.rules.org_ip_allowlist(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_org_ip_allowlist_title(self) -> None:
        rule = github.rules.org_ip_allowlist()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.org_ip_allowlist_github___ip_allow_list_modified
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "GitHub Org IP Allow list modified by cat.")
