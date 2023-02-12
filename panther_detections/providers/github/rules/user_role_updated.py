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
    "user_role_updated"
]


def user_role_updated(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a GitHub user role is upgraded to an admin or downgraded to a member"""
    
    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"Org owner [{event.udm('actor_user')}] updated user's "
    #        f"[{event.get('user')}] role ('admin' or 'member')"
    #    )

    
    
    
    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub User Role Updated",
        rule_id="GitHub.User.RoleUpdated",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityHigh,
        description="Detects when a GitHub user role is upgraded to an admin or downgraded to a member",
        tags=['GitHub', 'Persistence:Account Manipulation'],
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        #reference=,
        #runbook=,
        alert_title=_title,
        #summary_attrs=,
        #threshold=,
        #alert_context=,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    return event.get("action") == "org.update_member"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Member Updated",
                    expect_match=True,
                    data=sample_logs.user_role_updated_github___member_updated
                ),
                detection.JSONUnitTest(
                    name="GitHub - Member Updated",
                    expect_match=False,
                    data=sample_logs.user_role_updated_github___member_updated
                ),
                
            ]
        )
    )