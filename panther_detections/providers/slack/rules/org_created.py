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
    "org_created"
]


def org_created(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack organization is created"""
        #from panther_base_helpers import slack_alert_context

    
    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack Organization Created",
        rule_id="Slack.AuditLogs.OrgCreated",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityLow,
        description="Detects when a Slack organization is created",
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
    #    return event.get("action") == "organization_created"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Organization Created",
                    expect_match=True,
                    data=sample_logs.org_created_organization_created
                ),
                detection.JSONUnitTest(
                    name="Organization Deleted",
                    expect_match=False,
                    data=sample_logs.org_created_organization_deleted
                ),
                
            ]
        )
    )