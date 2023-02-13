import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesPublicRepositoryCreated(unittest.TestCase):
    def test_public_repository_created(self) -> None:
        name_override = "Override Name"
        rule = github.rules.public_repository_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_public_repository_created_title(self) -> None:
        rule = github.rules.public_repository_created()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.public_repository_created_private_repo_created
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(
            title,
            "Repository [example-io/oops] "
            "created with public status by Github user [example-actor].",
        )
