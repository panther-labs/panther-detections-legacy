import unittest
import json
from panther_sdk import detection, PantherEvent
from panther_detections.providers import teleport


class TestRulesNetworkScanning(unittest.TestCase):
    def test_network_scanning(self) -> None:
        name_override = "Override Name"
        rule = teleport.rules.network_scanning(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_network_scanning_title(self) -> None:
        rule = teleport.rules.network_scanning()
        evt = PantherEvent(json.loads(teleport.sample_logs.nmap_running_from_crontab))

        title = rule.alert_title(evt) #type: ignore

        self.assertEqual(title, "User [panther] has issued a network scan with [nmap]")
    
    
    