import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import DLP_ACTIONS, rule_tags, slack_alert_context

__all__ = ["dlp_modified"]
__all__ = ["dlp_modified"]


def dlp_modified(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Data Loss Prevention (DLP) rule has been deactivated or a violation has been deleted"""

    def _title(event: PantherEvent) -> str:
        if event.get("action") == "native_dlp_rule_deactivated":
            return "Slack DLP Rule Deactivated"
        return "Slack DLP Violation Deleted"

    # DLP violations can be removed by security engineers in the case of FPs
    # We still want to alert on these, however those should not constitute a High severity
    def _severity(event: PantherEvent) -> str:
        if event.get("action") == "native_dlp_violation_deleted":
            return "Medium"
        return "High"

    return detection.Rule(
        overrides=overrides,
        name="Slack DLP Modified",
        rule_id="Slack.AuditLogs.DLPModified",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="Detects when a Data Loss Prevention (DLP) rule has been "
        "deactivated or a violation has been deleted",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        alert_title=_title,
        summary_attrs=["action", "p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_in("action", DLP_ACTIONS)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Native DLP Rule Deactivated",
                    expect_match=True,
                    data=sample_logs.dlp_modified_native_dlp_rule_deactivated,
                ),
                detection.JSONUnitTest(
                    name="Native DLP Violation Deleted",
                    expect_match=True,
                    data=sample_logs.dlp_modified_native_dlp_violation_deleted,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.dlp_modified_user_logout
                ),
            ]
        ),
    )
