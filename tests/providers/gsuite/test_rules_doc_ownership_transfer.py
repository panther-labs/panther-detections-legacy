import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesDocOwnershipTransfer(unittest.TestCase):
    def test_doc_ownership_transfer(self) -> None:
        name_override = "Override Name"

        tags_override = ["new tag", "new tag2"]

        rule = gsuite.rules.doc_ownership_transfer(
            overrides=detection.RuleOverrides(
                name=name_override,
                tags=tags_override
            )
        )

        self.assertEqual(rule.name, name_override)
        self.assertEqual(rule.tags, tags_override)
