import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["private_channel_made_public"]
__all__ = ["private_channel_made_public"]


def private_channel_made_public(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a channel that was previously private is made public"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Private Channel Made Public",
        rule_id="Slack.AuditLogs.PrivateChannelMadePublic",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityHigh,
        description="Detects when a channel that was previously private is made public",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "private_channel_converted_to_public")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Private Channel Made Public",
                    expect_match=True,
                    data=sample_logs.private_channel_made_public_private_channel_made_public,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.private_channel_made_public_user_logout
                ),
            ]
        ),
    )
