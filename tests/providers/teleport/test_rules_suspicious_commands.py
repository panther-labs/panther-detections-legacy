import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import teleport


class TestRulesSuspiciousCommands(unittest.TestCase):
    def test_suspicious_commands(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.suspicious_commands(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_suspicious_commands_title(self) -> None:
        rule = teleport.rules.suspicious_commands()
        evt = PantherEvent(json.loads(teleport.sample_logs.netcat_command))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [panther] has executed the command [nc]")
    
    
    