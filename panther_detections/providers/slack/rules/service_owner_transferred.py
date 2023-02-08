import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["service_owner_transferred"]


def service_owner_transferred(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects transferring of service owner on request from primary owner"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Service Owner Transferred",
        rule_id="Slack.AuditLogs.ServiceOwnerTransferred",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityCritical,
        description="Detects transferring of service owner on request from primary owner",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "service_owner_transferred")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Service Owner Transferred",
                    expect_match=True,
                    data=sample_logs.service_owner_transferred_service_owner_transferred,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.service_owner_transferred_user_logout
                ),
            ]
        ),
    )
