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
    "user_modified"
]


def user_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Panther user's role has been modified. This could mean password, email, or role has changed for the user."""
        #import panther_event_type_helpers as event_type
    #from panther_base_helpers import deep_get
    #PANTHER_USER_ACTIONS = [
    #    event_type.USER_ACCOUNT_MODIFIED,
    #]

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"The user account "
    #        f"{deep_get(event, 'actionParams', 'dynamic', 'input', 'email', default='<UNKNOWN_USER>')}"
    #        f" was modified by {event.udm('actor_user')}"
    #    )

    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return {
    #        "user": event.udm("actor_user"),
    #        "change_target": deep_get(
    #            event, "actionParams", "dynamic", "input", "email", default="<UNKNOWN_USER>"
    #        ),
    #        "ip": event.udm("source_ip"),
    #    }

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="A User's Panther Account was Modified",
        rule_id="Panther.User.Modified",
        log_types=[schema.PantherAudit],
        severity=detection.SeverityHigh,
        description="A Panther user's role has been modified. This could mean password, email, or role has changed for the user.",
        tags=['DataModel', 'Persistence:Account Manipulation'],
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        #reference=,
        runbook="Validate that this user modification was intentional.",
        alert_title=_title,
        summary_attrs=['p_any_ip_addresses'],
        #threshold=,
        alert_context=_alert_context,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    if event.udm("event_type") not in PANTHER_USER_ACTIONS:
    #        return False
    #    return event.get("actionResult") == "SUCCEEDED"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Role Created",
                    expect_match=False,
                    data=sample_logs.user_modified_admin_role_created
                ),
                detection.JSONUnitTest(
                    name="Users's email was changed",
                    expect_match=True,
                    data=sample_logs.user_modified_users's_email_was_changed
                ),
                detection.JSONUnitTest(
                    name="Users's role was changed",
                    expect_match=True,
                    data=sample_logs.user_modified_users's_role_was_changed
                ),
                
            ]
        )
    )