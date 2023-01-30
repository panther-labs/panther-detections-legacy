import unittest

from panther_sdk import detection
from panther_detections.providers import box


class TestRulesAccessGranted(unittest.TestCase):
    def test_access_granted(self) -> None:
        name_override = "Override Name"
        rule = box.rules.access_granted(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)

    def test_my_box_reference(self) -> None:

        rule = box.rules.access_granted(
           overrides=detection.RuleOverrides(reference="MyNewReference"))
        
        self.assertEqual(rule.reference, "MyNewReference")


    