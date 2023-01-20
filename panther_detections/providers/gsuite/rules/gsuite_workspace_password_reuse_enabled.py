import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_password_reuse_enabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Enabled Password Reuse"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Password Reuse Has Been Enabled",
        rule_id="GSuite.Workspace.PasswordReuseEnabled",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0006:T1110']},
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Enabled Password Reuse",
        reference="https://support.google.com/a/answer/139399?hl=en#",
        runbook="Verify the intent of this Password Reuse Setting Change. If intent cannot be verified, then a search on the actor's other activities is advised.",
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
                    name="Workspace Admin Enabled Password Reuse",
                    expect_match=True,
                    data=sample_logs.workspace_admin_enabled_password_reuse
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