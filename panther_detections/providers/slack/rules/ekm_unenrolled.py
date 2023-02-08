import typing

from panther_sdk import detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["ekm_unenrolled"]
__all__ = ["ekm_unenrolled"]


def ekm_unenrolled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a workspace is no longer enrolled or managed by EKM"""

    return detection.Rule(
        overrides=overrides,
        name="Slack App Access Expanded",
        rule_id="Slack.AuditLogs.EKMUnenrolled",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityCritical,
        description="Detects when a workspace is no longer enrolled or managed by EKM",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # Only alert on the ekm_unenrolled action
            match_filters.deep_equal("action", "ekm_unenrolled")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="EKM Unenrolled", expect_match=True, data=sample_logs.ekm_unenrolled_ekm_unenrolled
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.ekm_unenrolled_user_logout
                ),
            ]
        ),
    )
