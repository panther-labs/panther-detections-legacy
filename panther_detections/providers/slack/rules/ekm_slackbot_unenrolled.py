import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["ekm_slackbot_unenrolled"]
__all__ = ["ekm_slackbot_unenrolled"]


def ekm_slackbot_unenrolled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a workspace is longer enrolled in EKM"""

    return detection.Rule(
        overrides=overrides,
        name="Slack EKM Slackbot Unenrolled",
        rule_id="Slack.AuditLogs.EKMSlackbotUnenrolled",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityHigh,
        description="Detects when a workspace is longer enrolled in EKM",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # Only alert on the `ekm_slackbot_unenroll_notification_sent` action
            match_filters.deep_equal("action", "ekm_slackbot_unenroll_notification_sent")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="EKM Slackbot Unenrolled",
                    expect_match=True,
                    data=sample_logs.ekm_slackbot_unenrolled_ekm_slackbot_unenrolled,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.ekm_slackbot_unenrolled_user_logout
                ),
            ]
        ),
    )
