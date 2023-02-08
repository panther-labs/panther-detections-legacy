import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["potentially_malicious_file_shared"]
__all__ = ["potentially_malicious_file_shared"]


def potentially_malicious_file_shared(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has had its permission scopes expanded"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Potentially Malicious File Shared",
        rule_id="Slack.AuditLogs.PotentiallyMaliciousFileShared",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityCritical,
        description="Detects when a Slack App has had its permission scopes expanded",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "file_malicious_content_detected")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Malicious Content Detected",
                    expect_match=True,
                    data=sample_logs.potentially_malicious_file_shared_malicious_content_detected,
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.potentially_malicious_file_shared_user_logout,
                ),
            ]
        ),
    )
