import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["service_owner_transferred"]


def service_owner_transferred(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects transferring of service owner on request from primary owner"""
    # from panther_base_helpers import slack_alert_context

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack Service Owner Transferred",
        rule_id="Slack.AuditLogs.ServiceOwnerTransferred",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityCritical,
        description="Detects transferring of service owner on request from primary owner",
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
            #    return event.get("action") == "service_owner_transferred"
        ],
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
