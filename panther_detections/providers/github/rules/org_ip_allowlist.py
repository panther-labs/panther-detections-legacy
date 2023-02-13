from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import ALLOWLIST_ACTIONS, rule_tags

__all__ = ["org_ip_allowlist"]


def org_ip_allowlist(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects changes to a GitHub Org IP Allow List"""

    def _title(event: PantherEvent) -> str:
        return f"GitHub Org IP Allow list modified by {event.get('actor')}."

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Org IP Allow List modified",
        rule_id="GitHub.Org.IpAllowlist",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityMedium,
        description="Detects changes to a GitHub Org IP Allow List",
        tags=rule_tags("Persistence:Account Manipulation"),
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        # reference=,
        runbook="Verify that the change was authorized and appropriate.",
        alert_title=_title,
        summary_attrs=["actor", "action"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_starts_with("action", "ip_allow_list"),
            match_filters.deep_in("action", ALLOWLIST_ACTIONS),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - IP Allow list modified",
                    expect_match=True,
                    data=sample_logs.org_ip_allowlist_github___ip_allow_list_modified,
                ),
                detection.JSONUnitTest(
                    name="GitHub - IP Allow list disabled",
                    expect_match=True,
                    data=sample_logs.org_ip_allowlist_github___ip_allow_list_disabled,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Non IP Allow list action",
                    expect_match=False,
                    data=sample_logs.org_ip_allowlist_github___non_ip_allow_list_action,
                ),
            ]
        ),
    )
