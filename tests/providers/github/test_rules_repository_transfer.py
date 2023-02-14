import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesRepositoryTransfer(unittest.TestCase):
    def test_repository_transfer(self) -> None:
        name_override = "Override Name"
        rule = github.rules.repository_transfer(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_repository_transfer_title(self) -> None:
        rule = github.rules.repository_transfer()
        evt = PantherEvent(
            json.loads(github.sample_logs.repository_transfer_repo_transfer_outgoing)
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "Github User [user-name] transferred repository [your-organization/project_repo] in [your-organization].",
        )
