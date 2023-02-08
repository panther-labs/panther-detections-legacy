import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["user_privilege_escalation"]


def user_privilege_escalation(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has had its permission scopes expanded"""
    # from panther_base_helpers import slack_alert_context
    # USER_PRIV_ESC_ACTIONS = {
    #    "owner_transferred": "Slack Owner Transferred",
    #    "permissions_assigned": "Slack User Assigned Permissions",
    #    "role_change_to_admin": "Slack User Made Admin",
    #    "role_change_to_owner": "Slack User Made Owner",
    # }

    # def _title(event: PantherEvent) -> str:
    #    if event.get("action") in USER_PRIV_ESC_ACTIONS:
    #        return USER_PRIV_ESC_ACTIONS.get(event.get("action"))
    #    return "Slack User Privilege Escalation"

    # def _severity(event: PantherEvent) -> str:
    #    # Downgrade severity for users assigned permissions
    #    # TODO: Add case to check for admin privileges to escalate to Critical
    #    if event.get("action") == "permissions_assigned":
    #        return "Medium"
    #    return "High"

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack User Privilege Escalation",
        rule_id="Slack.AuditLogs.UserPrivilegeEscalation",
        log_types=["Slack.AuditLogs"],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="Detects when a Slack App has had its permission scopes expanded",
        tags=["Slack"],
        # reports=,
        reference="https://api.slack.com/admins/audit-logs",
        # runbook=,
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    return event.get("action") in USER_PRIV_ESC_ACTIONS
        ],
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
