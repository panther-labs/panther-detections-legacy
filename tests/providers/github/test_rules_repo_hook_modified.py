import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesRepoHookModified(unittest.TestCase):
    def test_repo_hook_modified(self) -> None:
        name_override = "Override Name"
        rule = github.rules.repo_hook_modified(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_repo_hook_modified_title(self) -> None:
        rule = github.rules.repo_hook_modified()
        evt = PantherEvent(
            json.loads(github.sample_logs.repo_hook_modified_github___webhook_deleted)
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "web hook deleted in repository [<UNKNOWN_REPO>]")

    def test_repo_hook_modified_severity(self) -> None:
        rule = github.rules.repo_hook_modified()
        evt = PantherEvent(
            json.loads(github.sample_logs.repo_hook_modified_github___webhook_deleted)
        )
        sev = rule.severity.func(evt)

        self.assertEqual(sev, detection.SeverityInfo)
