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
    "private_channel_made_public"
]


def private_channel_made_public(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a channel that was previously private is made public"""
        #from panther_base_helpers import slack_alert_context

    
    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack Private Channel Made Public",
        rule_id="Slack.AuditLogs.PrivateChannelMadePublic",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityHigh,
        description="Detects when a channel that was previously private is made public",
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
    #    return event.get("action") == "private_channel_converted_to_public"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Private Channel Made Public",
                    expect_match=True,
                    data=sample_logs.private_channel_made_public_private_channel_made_public
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.private_channel_made_public_user_logout
                ),
                
            ]
        )
    )