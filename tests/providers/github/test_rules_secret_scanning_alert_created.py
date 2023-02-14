import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesSecretScanningAlertCreated(unittest.TestCase):
    def test_secret_scanning_alert_created(self) -> None:
        name_override = "Override Name"
        rule = github.rules.secret_scanning_alert_created(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_secret_scanning_alert_created_title(self) -> None:
        rule = github.rules.secret_scanning_alert_created()
        evt = PantherEvent(
            json.loads(
                github.sample_logs.secret_scanning_alert_created_github_detected_a_secret
            )
        )

        title = rule.alert_title(evt)  # type: ignore

        self.assertEqual(title, "Github detected a secret in acme-co/website (#1792)")
