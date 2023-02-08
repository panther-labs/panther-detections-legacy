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
    "app_access_expanded"
]


def app_access_expanded(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack App has had its permission scopes expanded"""
        #from panther_base_helpers import deep_get, slack_alert_context
    #ACCESS_EXPANDED_ACTIONS = [
    #    "app_scopes_expanded",
    #    "app_resources_added",
    #    "app_resources_granted",
    #    "bot_token_upgraded",
    #]

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"Slack App [{deep_get(event, 'entity', 'app', 'name')}] "
    #        f"Access Expanded by [{deep_get(event, 'actor', 'user', 'name')}]"
    #    )

    # def _severity(event: PantherEvent) -> str:
    #    # Used to escalate to High/Critical if the app is granted admin privileges
    #    # May want to escalate to "Critical" depending on security posture
    #    if "admin" in deep_get(event, "entity", "app", "scopes", default=[]):
    #        return "High"
    #    # Fallback method in case the admin scope is not directly mentioned in entity for whatever
    #    if "admin" in deep_get(event, "details", "new_scope", default=[]):
    #        return "High"
    #    if "admin" in deep_get(event, "details", "bot_scopes", default=[]):
    #        return "High"
    #    return "Medium"

    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    context = slack_alert_context(event)
    #    # Diff previous and new scopes
    #    new_scopes = deep_get(event, "details", "new_scopes", default=[])
    #    prv_scopes = deep_get(event, "details", "previous_scopes", default=[])
    #    context["scopes_added"] = [x for x in new_scopes if x not in prv_scopes]
    #    context["scoped_removed"] = [x for x in prv_scopes if x not in new_scopes]
    #    return context

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack App Access Expanded",
        rule_id="Slack.AuditLogs.AppAccessExpanded",
        log_types=['Slack.AuditLogs'],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityMedium),
        description="Detects when a Slack App has had its permission scopes expanded",
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
    #    return event.get("action") in ACCESS_EXPANDED_ACTIONS

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="App Scopes Expanded",
                    expect_match=True,
                    data=sample_logs.app_access_expanded_app_scopes_expanded
                ),
                detection.JSONUnitTest(
                    name="App Resources Added",
                    expect_match=True,
                    data=sample_logs.app_access_expanded_app_resources_added
                ),
                detection.JSONUnitTest(
                    name="App Resources Granted",
                    expect_match=True,
                    data=sample_logs.app_access_expanded_app_resources_granted
                ),
                detection.JSONUnitTest(
                    name="Bot Token Upgraded",
                    expect_match=True,
                    data=sample_logs.app_access_expanded_bot_token_upgraded
                ),
                detection.JSONUnitTest(
                    name="User Logout",
                    expect_match=False,
                    data=sample_logs.app_access_expanded_user_logout
                ),
                
            ]
        )
    )