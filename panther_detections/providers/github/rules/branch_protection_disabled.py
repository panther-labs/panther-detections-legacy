from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import github_alert_context, rule_tags

__all__ = ["branch_protection_disabled"]


def branch_protection_disabled(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Disabling branch protection controls could indicate malicious use of admin
    credentials in an attempt to hide activity."""

    def _title(event: PantherEvent) -> str:
        return (
            f"A branch protection was removed from the "
            f"repository [{event.get('repo', '<UNKNOWN_REPO>')}] "
            f"by [{event.get('actor', '<UNKNOWN_ACTOR>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Branch Protection Disabled",
        rule_id="GitHub.Branch.ProtectionDisabled",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityHigh,
        description="Disabling branch protection controls could indicate"
        "malicious use of admin credentials in an attempt to hide activity.",
        tags=rule_tags("Initial Access:Supply Chain Compromise"),
        reports={"MITRE ATT&CK": ["TA0001:T1195"]},
        # reference=,
        runbook="Verify that branch protection should be disabled on the repository and re-enable as necessary.",
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        alert_context=github_alert_context,
        # alert_grouping=,
        filters=[match_filters.deep_equal("action", "protected_branch.destroy")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Branch Protection Disabled",
                    expect_match=True,
                    data=sample_logs.branch_protection_disabled_github___branch_protection_disabled,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Protected Branch Name Updated",
                    expect_match=False,
                    data=sample_logs.branch_protection_disabled_github___protected_branch_name_updated,
                ),
            ]
        ),
    )
