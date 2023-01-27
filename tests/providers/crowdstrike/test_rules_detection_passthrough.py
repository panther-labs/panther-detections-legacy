import unittest

from panther_sdk import detection
from panther_detections.providers import crowdstrike


class TestRulesDetectionPassthrough(unittest.TestCase):
    def test_detection_passthrough(self) -> None:
        name_override = "Override Name"
        rule = crowdstrike.rules.detection_passthrough(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertIsInstance(rule, detection.Rule)
        self.assertEqual(rule.name, name_override)

