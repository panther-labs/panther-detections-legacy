import unittest
from panther_sdk import detection, PantherEvent
from panther_detections.providers import github


class TestRulesAdvancedSecurityChange(unittest.TestCase):
    def test_advanced_security_change(self) -> None:
        name_override = "Override Name"
        rule = github.rules.advanced_security_change(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_advanced_security_change_title(self) -> None:
        rule = github.rules.advanced_security_change()
        test_evt = PantherEvent({"action": "secret_scanning"})

        title = rule.alert_title(test_evt)  # type: ignore

        self.assertEqual(
            title, "Change detected to GitHub Advanced Security - secret_scanning"
        )

    def test_advanced_security_change_group_by(self) -> None:
        rule = github.rules.advanced_security_change()
        test_evt = PantherEvent({"action": "repo.transfer", "actor": "bobert"})
        key = rule.alert_grouping.group_by(test_evt)

        self.assertEqual(key, "bobert_repo.transfer")

    def test_advanced_security_change_severity(self) -> None:
        rule = github.rules.advanced_security_change()
        test_evt = PantherEvent({"action": "repo.access", "actor": "cat"})
        sev = rule.severity.func(test_evt)

        self.assertEqual(sev, "Low")
