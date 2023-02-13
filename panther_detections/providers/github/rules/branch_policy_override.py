from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["branch_policy_override"]


def branch_policy_override(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Bypassing branch protection controls could indicate
    malicious use of admin credentials in an attempt to hide activity."""

    def _title(event: PantherEvent) -> str:
        return (
            f"A branch protection requirement in the repository"
            f" [{event.get('repo', '<UNKNOWN_REPO>')}]"
            f" was overridden by user [{event.get('actor')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Branch Protection Policy Override",
        rule_id="GitHub.Branch.PolicyOverride",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityHigh,
        description="Bypassing branch protection controls could indicate"
        "malicious use of admin credentials in an attempt to hide activity.",
        tags=rule_tags("Initial Access:Supply Chain Compromise"),
        reports={"MITRE ATT&CK": ["TA0001:T1195"]},
        # reference=,
        runbook="Verify that the GitHub admin performed this activity and validate its use.",
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[match_filters.deep_equal("action", "protected_branch.policy_override")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Branch Protection Policy Override",
                    expect_match=True,
                    data=sample_logs.branch_policy_override_github___branch_protection_policy_override,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Protected Branch Name Updated",
                    expect_match=False,
                    data=sample_logs.branch_policy_override_github___protected_branch_name_updated,
                ),
            ]
        ),
    )
