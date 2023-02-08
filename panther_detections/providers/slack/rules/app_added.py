from typing import Any, Dict, List

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["app_added"]
__all__ = ["app_added"]


def app_added(
    pre_filters: List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has been added to a workspace"""

    APP_ADDED_ACTIONS = [
        "app_approved",
        "app_installed",
        "org_app_workspace_added",
    ]

    def _title(event: PantherEvent) -> str:
        return (
            f"Slack App [{event.deep_get( 'entity', 'app', 'name')}] "
            f"Added by [{event.deep_get( 'actor', 'user', 'name')}]"
        )

    def _severity(event: PantherEvent) -> str:
        # Used to escalate to High/Critical if the app is granted admin privileges
        # May want to escalate to "Critical" depending on security posture
        if "admin" in event.deep_get("entity", "app", "scopes"):
            return "High"
        # Fallback method in case the admin scope is not directly mentioned in entity for whatever
        if "admin" in event.deep_get("details", "new_scope"):
            return "High"
        if "admin" in event.deep_get("details", "bot_scopes"):
            return "High"
        return "Medium"

    def _alert_context(event: PantherEvent) -> Dict[str, Any]:
        context = slack_alert_context(event)
        context["scopes"] = event.deep_get("entity", "scopes")
        return context

    return detection.Rule(
        overrides=overrides,
        name="Slack App Added",
        rule_id="Slack.AuditLogs.AppAdded",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityMedium),
        description="Detects when a Slack App has been added to a workspace",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_in("action", APP_ADDED_ACTIONS)],
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
