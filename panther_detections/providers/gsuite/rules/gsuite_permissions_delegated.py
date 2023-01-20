import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_permissions_delegated(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was granted new administrator privileges."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="--DEPRECATED-- GSuite User Delegated Admin Permissions",
        rule_id="GSuite.PermisssionsDelegated",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityLow,
        description="A GSuite user was granted new administrator privileges.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings#ASSIGN_ROLE",
        runbook="Valdiate that this users should have these permissions and they are not the result of a privilege escalation attack.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['actor:email']
        ,
        threshold="",
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Other Admin Action",
                    expect_match=False,
                    data=sample_logs.other_admin_action
                ),
                detection.JSONUnitTest(
                    name="Privileges Assigned",
                    expect_match=True,
                    data=sample_logs.privileges_assigned
                ),
                
            ]
        )
    )