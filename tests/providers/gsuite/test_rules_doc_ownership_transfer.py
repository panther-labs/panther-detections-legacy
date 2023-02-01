import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesDocOwnershipTransfer(unittest.TestCase):
    def test_doc_ownership_transfer(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.doc_ownership_transfer(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
