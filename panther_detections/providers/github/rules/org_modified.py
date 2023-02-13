from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["org_modified"]


def org_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a user is added or removed from a GitHub Org."""

    def _title(event: PantherEvent) -> str:
        action = event.get("action")
        if event.get("action") == "org.add_member":
            action = "added"
        elif event.get("action") == "org.remove_member":
            action = "removed"
        return (
            f"GitHub.Audit: User [{event.get('actor_user')}] {action} "
            # f"GitHub.Audit: User [{event.udm('actor_user')}] {action} "
            f"{event.get('user', '<UNKNOWN_USER>')} to org [{event.get('org','<UNKNOWN_ORG>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub User Added or Removed from Org",
        rule_id="GitHub.Org.Modified",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityInfo,
        description="Detects when a user is added or removed from a GitHub Org.",
        tags=["GitHub", "Initial Access:Supply Chain Compromise"],
        reports={"MITRE ATT&CK": ["TA0001:T1195"]},
        # reference=,
        # runbook=,
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[match_filters.deep_in("action", {"org.add_member", "org.remove_member"})],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Team Deleted",
                    expect_match=False,
                    data=sample_logs.org_modified_github___team_deleted,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Org - User Added",
                    expect_match=True,
                    data=sample_logs.org_modified_github___org___user_added,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Org - User Removed",
                    expect_match=True,
                    data=sample_logs.org_modified_github___org___user_removed,
                ),
            ]
        ),
    )
