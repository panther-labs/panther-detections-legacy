import unittest

from panther_sdk import detection
from panther_detections.providers import gsuite


class TestRulesWorkspaceTrustedDomainsAllowlist(unittest.TestCase):
    def test_workspace_trusted_domains_allowlist(self) -> None:
        name_override = "Override Name"
        rule = gsuite.rules.workspace_trusted_domains_allowlist(
            overrides=detection.RuleOverrides(name=name_override)
        )

        self.assertEqual(rule.name, name_override)
    