import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["app_removed"]
__all__ = ["app_removed"]


def app_removed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has been removed"""
    APP_REMOVED_ACTIONS = [
        "app_restricted",
        "app_uninstalled",
        "org_app_workspace_removed",
    ]

    def _title(event: PantherEvent) -> str:
        return (
            f"Slack App [{event.deep_get('entity', 'app', 'name')}] "
            f"Removed by [{event.deep_get('actor', 'user', 'name')}]"
        )

    return detection.Rule(
        overrides=overrides,
        name="Slack App Access Expanded",
        rule_id="Slack.AuditLogs.AppRemoved",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityMedium,
        description="Detects when a Slack App has been removed",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_in("action", APP_REMOVED_ACTIONS)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="App Restricted", expect_match=True, data=sample_logs.app_removed_app_restricted
                ),
                detection.JSONUnitTest(
                    name="App Uninstalled", expect_match=True, data=sample_logs.app_removed_app_uninstalled
                ),
                detection.JSONUnitTest(
                    name="App removed from workspace",
                    expect_match=True,
                    data=sample_logs.app_removed_app_removed_from_workspace,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.app_removed_user_logout
                ),
            ]
        ),
    )
