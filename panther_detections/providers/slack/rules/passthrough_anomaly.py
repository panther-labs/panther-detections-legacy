import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["passthrough_anomaly"]
__all__ = ["passthrough_anomaly"]


def passthrough_anomaly(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Passthrough for anomalies detected by Slack"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Anomaly Detected",
        rule_id="Slack.AuditLogs.PassthroughAnomaly",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityCritical,
        description="Passthrough for anomalies detected by Slack",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "anomaly")],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Name", expect_match=True, data=sample_logs.passthrough_anomaly_name),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.passthrough_anomaly_user_logout
                ),
            ]
        ),
    )
