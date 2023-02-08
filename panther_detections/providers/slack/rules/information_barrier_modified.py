import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import INFORMATION_BARRIER_ACTIONS, rule_tags, slack_alert_context

__all__ = ["information_barrier_modified"]
__all__ = ["information_barrier_modified"]


def information_barrier_modified(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack information barrier is deleted/updated"""

    def _title(event: PantherEvent) -> str:
        if event.get("action") in INFORMATION_BARRIER_ACTIONS:
            return INFORMATION_BARRIER_ACTIONS.get(event.get("action"))
        return "Slack Information Barrier Modified"

    return detection.Rule(
        overrides=overrides,
        name="Slack Information Barrier Modified",
        rule_id="Slack.AuditLogs.InformationBarrierModified",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityMedium,
        description="Detects when a Slack information barrier is deleted/updated",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        alert_title=_title,
        summary_attrs=["action", "p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_in("action", INFORMATION_BARRIER_ACTIONS)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Information Barrier Deleted",
                    expect_match=True,
                    data=sample_logs.information_barrier_modified_information_barrier_deleted,
                ),
                detection.JSONUnitTest(
                    name="Information Barrier Updated",
                    expect_match=True,
                    data=sample_logs.information_barrier_modified_information_barrier_updated,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.information_barrier_modified_user_logout
                ),
            ]
        ),
    )
