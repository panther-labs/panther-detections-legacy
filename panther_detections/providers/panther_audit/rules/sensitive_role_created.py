import typing
from panther_sdk import PantherEvent, detection, schema
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = [
    "sensitive_role_created"
]


def sensitive_role_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Panther user role has been created that contains admin level permissions."""
        #import panther_event_type_helpers as event_type
    #from panther_base_helpers import deep_get
    #PANTHER_ADMIN_PERMISSIONS = [
    #    "UserModify",
    #    "OrganizationAPITokenModify",
    #    "OrganizationAPITokenRead",
    #    "GeneralSettingsModify",
    #]
    #PANTHER_ROLE_ACTIONS = [
    #    event_type.USER_GROUP_CREATED,
    #    event_type.USER_GROUP_MODIFIED,
    #]

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"Role with Admin Permissions created by {event.udm('actor_user')}"
    #        f"Role Name: {deep_get(event, 'actionParams', 'input' ,'name')}"
    #    )

    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return {
    #        "user": event.udm("actor_user"),
    #        "role_name": deep_get(event, "actionParams", "name"),
    #        "ip": event.udm("source_ip"),
    #    }

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="A User Role with Sensitive Permissions has been Created",
        rule_id="Panther.Sensitive.Role",
        log_types=[schema.PantherAudit],
        severity=detection.SeverityHigh,
        description="A Panther user role has been created that contains admin level permissions.",
        tags=['DataModel', 'Persistence:Account Manipulation'],
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        #reference=,
        runbook="Contact the creator of this role to ensure its creation was appropriate.",
        alert_title=_title,
        summary_attrs=['p_any_ip_addresses'],
        #threshold=,
        alert_context=_alert_context,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    if event.udm("event_type") not in PANTHER_ROLE_ACTIONS:
    #        return False
    #    role_permissions = set(deep_get(event, "actionParams", "input", "permissions", default=""))
    #    return (
    #        len(set(PANTHER_ADMIN_PERMISSIONS).intersection(role_permissions)) > 0
    #        and event.get("actionResult") == "SUCCEEDED"
    #    )

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Role Created",
                    expect_match=True,
                    data=sample_logs.sensitive_role_created_admin_role_created
                ),
                detection.JSONUnitTest(
                    name="Non-Admin Role Created",
                    expect_match=False,
                    data=sample_logs.sensitive_role_created_non_admin_role_created
                ),
                detection.JSONUnitTest(
                    name="nonetype error",
                    expect_match=False,
                    data=sample_logs.sensitive_role_created_nonetype_error
                ),
                
            ]
        )
    )