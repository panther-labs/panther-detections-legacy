import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["ekm_config_changed"]


def ekm_config_changed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when the logging settings for a workspace's EKM configuration has changed"""

    return detection.Rule(
        overrides=overrides,
        name="Slack EKM Config Changed",
        rule_id="Slack.AuditLogs.EKMConfigChanged",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityHigh,
        description="Detects when the logging settings for a workspace's EKM configuration has changed",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # Only alert on the `ekm_logging_config_set` action
            match_filters.deep_equal("action", "ekm_logging_config_set")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="EKM Config Changed", expect_match=True, data=sample_logs.ekm_config_changed_ekm_config_changed
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.ekm_config_changed_user_logout
                ),
            ]
        ),
    )
