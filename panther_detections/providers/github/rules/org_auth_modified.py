from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import AUTH_CHANGE_EVENTS, github_alert_context, rule_tags

__all__ = ["org_auth_modified"]


def org_auth_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects changes to GitHub org authentication changes."""

    def _title(event: PantherEvent) -> str:
        return f"GitHub auth configuration was changed by {event.get('actor', '<UNKNOWN USER>')}"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Org Authentication Method Changed",
        rule_id="GitHub.Org.AuthChange",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityCritical,
        description="Detects changes to GitHub org authentication changes.",
        tags=rule_tags("Persistence:Account Manipulation"),
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        # reference=,
        runbook="Verify that the GitHub admin performed this activity and validate its use.",
        alert_title=_title,
        summary_attrs=["actor", "action"],
        # threshold=,
        alert_context=github_alert_context,
        # alert_grouping=,
        filters=[
            match_filters.deep_starts_with("action", "org."),
            match_filters.deep_in("action", AUTH_CHANGE_EVENTS),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Authentication Method Changed",
                    expect_match=True,
                    data=sample_logs.org_auth_modified_github___authentication_method_changed,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Non Auth Related Org Change",
                    expect_match=False,
                    data=sample_logs.org_auth_modified_github___non_auth_related_org_change,
                ),
            ]
        ),
    )
