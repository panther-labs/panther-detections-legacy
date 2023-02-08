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
    "intune_mdm_disabled"
]


def intune_mdm_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects the disabling of Microsoft Intune Enterprise MDM within Slack"""
        #from panther_base_helpers import slack_alert_context

    
    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack Intune MDM Disabled",
        rule_id="Slack.AuditLogs.IntuneMDMDisabled",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityCritical,
        description="Detects the disabling of Microsoft Intune Enterprise MDM within Slack",
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
    #    return event.get("action") == "intune_disabled"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Intune Disabled",
                    expect_match=True,
                    data=sample_logs.intune_mdm_disabled_intune_disabled
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.intune_mdm_disabled_user_logout
                ),
                
            ]
        )
    )