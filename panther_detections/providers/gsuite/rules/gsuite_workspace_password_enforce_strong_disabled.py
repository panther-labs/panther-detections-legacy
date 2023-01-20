import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_password_enforce_strong_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled The Enforcement Of Strong Passwords"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Strong Password Enforcement Has Been Disabled",
        rule_id="GSuite.Workspace.PasswordEnforceStrongDisabled",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0006:T1110']},
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Disabled The Enforcement Of Strong Passwords",
        reference="https://support.google.com/a/answer/139399?hl=en",
        runbook="Verify the intent of this Password Strength Setting Change. If intent cannot be verified, then a search on the actor's other activities is advised.",
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
                    name="Workspace Admin Disabled Strong Password Enforcement",
                    expect_match=True,
                    data=sample_logs.workspace_admin_disabled_strong_password_enforcement
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )