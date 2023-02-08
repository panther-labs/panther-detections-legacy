import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["app_removed"]


def app_removed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has been removed"""
    # from panther_base_helpers import deep_get, slack_alert_context
    # APP_REMOVED_ACTIONS = [
    #    "app_restricted",
    #    "app_uninstalled",
    #    "org_app_workspace_removed",
    # ]

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] "
    #        f"Removed by [{deep_get(event, 'actor', 'user', 'name')}]"
    #    )

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack App Access Expanded",
        rule_id="Slack.AuditLogs.AppRemoved",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityMedium,
        description="Detects when a Slack App has been removed",
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
            #    return event.get("action") in APP_REMOVED_ACTIONS
        ],
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
