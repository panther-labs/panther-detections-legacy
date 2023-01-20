import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_gmail_security_sandbox_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled The Security Sandbox"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Gmail Security Sandbox Disabled",
        rule_id="GSuite.Workspace.GmailSecuritySandboxDisabled",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0001:T1566']},
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Disabled The Security Sandbox",
        reference="https://support.google.com/a/answer/7676854?hl=en#zippy=%2Cfind-security-sandbox-settings%2Cabout-security-sandbox-rules-and-other-scans",
        runbook="Gmail's Security Sandbox enables rule based scanning of email content.
If this change was not intentional, inspect the other actions taken by this actor.",
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
                    name="Workspace Admin Disables Security Sandbox",
                    expect_match=True,
                    data=sample_logs.workspace_admin_disables_security_sandbox
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