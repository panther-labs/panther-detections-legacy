import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = [
    "information_barrier_modified"
]


def information_barrier_modified(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack information barrier is deleted/updated"""
        #from panther_base_helpers import slack_alert_context
    #INFORMATION_BARRIER_ACTIONS = {
    #    "barrier_deleted": "Slack Information Barrier Deleted",
    #    "barrier_updated": "Slack Information Barrier Updated",
    #}

    # def _title(event: PantherEvent) -> str:
    #    if event.get("action") in INFORMATION_BARRIER_ACTIONS:
    #        return INFORMATION_BARRIER_ACTIONS.get(event.get("action"))
    #    return "Slack Information Barrier Modified"

    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack Information Barrier Modified",
        rule_id="Slack.AuditLogs.InformationBarrierModified",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityMedium,
        description="Detects when a Slack information barrier is deleted/updated",
        tags=['Slack'],
        #reports=,
        reference="https://api.slack.com/admins/audit-logs",
        #runbook=,
        alert_title=_title,
        summary_attrs=['action', 'p_any_ip_addresses', 'p_any_emails'],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # def rule(event):
    #    return event.get("action") in INFORMATION_BARRIER_ACTIONS

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Information Barrier Deleted",
                    expect_match=True,
                    data=sample_logs.information_barrier_modified_information_barrier_deleted
                ),
                detection.JSONUnitTest(
                    name="Information Barrier Updated",
                    expect_match=True,
                    data=sample_logs.information_barrier_modified_information_barrier_updated
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.information_barrier_modified_user_logout
                ),
                
            ]
        )
    )