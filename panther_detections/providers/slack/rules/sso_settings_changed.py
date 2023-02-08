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
    "sso_settings_changed"
]


def sso_settings_changed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to Single Sign On (SSO) restrictions"""
        #from panther_base_helpers import slack_alert_context

    
    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    # TODO: Add details to context
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack SSO Settings Changed",
        rule_id="Slack.AuditLogs.SSOSettingsChanged",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityHigh,
        description="Detects changes to Single Sign On (SSO) restrictions",
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
    #    return event.get("action") == "pref.sso_setting_changed"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="SSO Setting Changed",
                    expect_match=True,
                    data=sample_logs.sso_settings_changed_sso_setting_changed
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.sso_settings_changed_user_logout
                ),
                
            ]
        )
    )