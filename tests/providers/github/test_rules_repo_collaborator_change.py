import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesRepoCollaboratorChange(unittest.TestCase):
    def test_repo_collaborator_change(self) -> None:
        name_override = "Override Name"
        rule = github.rules.repo_collaborator_change(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_repo_collaborator_change_title(self) -> None:
        rule = github.rules.repo_collaborator_change()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.repo_collaborator_change_github___collaborator_added
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "Repository collaborator [cat] added to repository my-org/my-repo."
            " View current collaborators here: https://github.com/my-org/my-repo/settings/access",
        )

    def test_repo_collaborator_change_severity(self) -> None:
        rule = github.rules.repo_collaborator_change()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.repo_collaborator_change_github___collaborator_added
            )
        )
        sev = rule.severity.func(evt)

        self.assertEqual(sev, detection.SeverityMedium)
