import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import USER_PRIV_ESC_ACTIONS, rule_tags, slack_alert_context

__all__ = ["user_privilege_escalation"]
__all__ = ["user_privilege_escalation"]


def user_privilege_escalation(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has had its permission scopes expanded"""

    def _title(event: PantherEvent) -> str:
        if event.get("action") in USER_PRIV_ESC_ACTIONS:
            return USER_PRIV_ESC_ACTIONS.get(event.get("action"))
        return "Slack User Privilege Escalation"

    def _severity(event: PantherEvent) -> str:
        # Downgrade severity for users assigned permissions
        # TODO: Add case to check for admin privileges to escalate to Critical
        if event.get("action") == "permissions_assigned":
            return "Medium"
        return "High"

    return detection.Rule(
        overrides=overrides,
        name="Slack User Privilege Escalation",
        rule_id="Slack.AuditLogs.UserPrivilegeEscalation",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="Detects when a Slack App has had its permission scopes expanded",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_in("action", USER_PRIV_ESC_ACTIONS)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Owner Transferred",
                    expect_match=True,
                    data=sample_logs.user_privilege_escalation_owner_transferred,
                ),
                detection.JSONUnitTest(
                    name="Permissions Assigned",
                    expect_match=True,
                    data=sample_logs.user_privilege_escalation_permissions_assigned,
                ),
                detection.JSONUnitTest(
                    name="Role Changed to Admin",
                    expect_match=True,
                    data=sample_logs.user_privilege_escalation_role_changed_to_admin,
                ),
                detection.JSONUnitTest(
                    name="Role Changed to Owner",
                    expect_match=True,
                    data=sample_logs.user_privilege_escalation_role_changed_to_owner,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.user_privilege_escalation_user_logout
                ),
            ]
        ),
    )
