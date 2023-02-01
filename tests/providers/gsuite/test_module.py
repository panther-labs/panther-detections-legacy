import typing
import unittest
from panther_sdk import PantherEvent
from panther_detections.providers import gsuite


class TestModule(unittest.TestCase):

    def test_create_alert_context(self) -> None:

        mock_data = {
            "p_any_ip_addresses": ["0.0.0.0"],
            "actor": "actor-value",
            "target": "target-value",
            "client": "client-value",
        }

        evt = PantherEvent(mock_data, data_model=None)
        ctx = gsuite.create_alert_context(evt)

        self.assertEqual(
            ctx,
            {
                "ips": mock_data["p_any_ip_addresses"],
                "actor": mock_data["actor"],
                "target": mock_data["target"],
                "client": mock_data["client"],
            },
        )
