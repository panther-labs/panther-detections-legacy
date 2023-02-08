import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["app_added"]


def app_added(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has been added to a workspace"""
    # from panther_base_helpers import deep_get, slack_alert_context
    # APP_ADDED_ACTIONS = [
    #    "app_approved",
    #    "app_installed",
    #    "org_app_workspace_added",
    # ]

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] "
    #        f"Added by [{deep_get(event, 'actor', 'user', 'name')}]"
    #    )

    # def _severity(event: PantherEvent) -> str:
    #    # Used to escalate to High/Critical if the app is granted admin privileges
    #    # May want to escalate to "Critical" depending on security posture
    #    if "admin" in deep_get(event, "entity", "app", "scopes"):
    #        return "High"
    #    # Fallback method in case the admin scope is not directly mentioned in entity for whatever
    #    if "admin" in deep_get(event, "details", "new_scope"):
    #        return "High"
    #    if "admin" in deep_get(event, "details", "bot_scopes"):
    #        return "High"
    #    return "Medium"

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    context = slack_alert_context(event)
    #    context["scopes"] = deep_get(event, "entity", "scopes")
    #    return context

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack App Added",
        rule_id="Slack.AuditLogs.AppAdded",
        log_types=["Slack.AuditLogs"],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityMedium),
        description="Detects when a Slack App has been added to a workspace",
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
            #    return event.get("action") in APP_ADDED_ACTIONS
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(name="App Approved", expect_match=True, data=sample_logs.app_added_app_approved),
                detection.JSONUnitTest(
                    name="App Installed", expect_match=True, data=sample_logs.app_added_app_installed
                ),
                detection.JSONUnitTest(
                    name="App added to workspace", expect_match=True, data=sample_logs.app_added_app_added_to_workspace
                ),
                detection.JSONUnitTest(name="User Logout", expect_match=False, data=sample_logs.app_added_user_logout),
            ]
        ),
    )
