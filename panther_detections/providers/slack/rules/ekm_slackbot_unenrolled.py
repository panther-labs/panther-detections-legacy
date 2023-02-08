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
    "ekm_slackbot_unenrolled"
]


def ekm_slackbot_unenrolled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a workspace is longer enrolled in EKM"""
        #from panther_base_helpers import slack_alert_context

    
    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack EKM Slackbot Unenrolled",
        rule_id="Slack.AuditLogs.EKMSlackbotUnenrolled",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityHigh,
        description="Detects when a workspace is longer enrolled in EKM",
        tags=['Slack'],
        #reports=,
        reference="https://api.slack.com/admins/audit-logs",
        #runbook=,
        alert_title=_title,
        summary_attrs=['p_any_ip_addresses', 'p_any_emails'],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # def rule(event):
    #    # Only alert on the `ekm_slackbot_unenroll_notification_sent` action
    #    return event.get("action") == "ekm_slackbot_unenroll_notification_sent"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="EKM Slackbot Unenrolled",
                    expect_match=True,
                    data=sample_logs.ekm_slackbot_unenrolled_ekm_slackbot_unenrolled
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.ekm_slackbot_unenrolled_user_logout
                ),
                
            ]
        )
    )