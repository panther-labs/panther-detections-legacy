import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["passthrough_anomaly"]


def passthrough_anomaly(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Passthrough for anomalies detected by Slack"""
    # from panther_base_helpers import slack_alert_context

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    # TODO: Add more details to context
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack Anomaly Detected",
        rule_id="Slack.AuditLogs.PassthroughAnomaly",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityCritical,
        description="Passthrough for anomalies detected by Slack",
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
            #    return event.get("action") == "anomaly"
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Name", expect_match=True, data=sample_logs.passthrough_anomaly_name),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.passthrough_anomaly_user_logout
                ),
            ]
        ),
    )
