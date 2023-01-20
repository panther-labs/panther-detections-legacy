import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_trusted_domains_allowlist(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Modified The Trusted Domains List"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Trusted Domain Allowlist Modified",
        rule_id="GSuite.Workspace.TrustedDomainsAllowlist",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Modified The Trusted Domains List",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings#ADD_TRUSTED_DOMAINS",
        runbook="Verify the intent of this modification. If intent cannot be verified, then an indicator search on the actor is advised.",
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
                    name="Workspace Admin Remove Trusted Domain",
                    expect_match=True,
                    data=sample_logs.workspace_admin_remove_trusted_domain
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Add Trusted Domain",
                    expect_match=True,
                    data=sample_logs.workspace_admin_add_trusted_domain
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )