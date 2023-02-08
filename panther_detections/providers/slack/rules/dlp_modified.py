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
    "dlp_modified"
]


def dlp_modified(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Data Loss Prevention (DLP) rule has been deactivated or a violation has been deleted"""
        #from panther_base_helpers import slack_alert_context
    #DLP_ACTIONS = [
    #    "native_dlp_rule_deactivated",
    #    "native_dlp_violation_deleted",
    #]

    # def _title(event: PantherEvent) -> str:
    #    if event.get("action") == "native_dlp_rule_deactivated":
    #        return "Slack DLP Rule Deactivated"
    #    return "Slack DLP Violation Deleted"
    ## DLP violations can be removed by security engineers in the case of FPs
    ## We still want to alert on these, however those should not constitute a High severity

    # def _severity(event: PantherEvent) -> str:
    #    if event.get("action") == "native_dlp_violation_deleted":
    #        return "Medium"
    #    return "High"

    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack DLP Modified",
        rule_id="Slack.AuditLogs.DLPModified",
        log_types=['Slack.AuditLogs'],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="Detects when a Data Loss Prevention (DLP) rule has been deactivated or a violation has been deleted",
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
    #    return event.get("action") in DLP_ACTIONS

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Native DLP Rule Deactivated",
                    expect_match=True,
                    data=sample_logs.dlp_modified_native_dlp_rule_deactivated
                ),
                detection.JSONUnitTest(
                    name="Native DLP Violation Deleted",
                    expect_match=True,
                    data=sample_logs.dlp_modified_native_dlp_violation_deleted
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.dlp_modified_user_logout
                ),
                
            ]
        )
    )