import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import teleport


class TestRulesCreateUserAccounts(unittest.TestCase):
    def test_create_user_accounts(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.create_user_accounts(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_create_user_accounts_title(self) -> None:
        rule = teleport.rules.create_user_accounts()
        evt = PantherEvent(json.loads(teleport.sample_logs.userdel_command))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [panther] has manually modified system users")
    
    
    