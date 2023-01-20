import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_gmail_default_routing_rule(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Modified A Default Routing Rule In Gmail"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Gmail Default Routing Rule Modified",
        rule_id="GSuite.Workspace.GmailDefaultRoutingRuleModified",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Modified A Default Routing Rule In Gmail",
        reference="https://support.google.com/a/answer/2368153?hl=en",
        runbook="Administrators use Default Routing to set up how inbound email is delivered within an organization. The configuration of the default routing rule needs to be inspected in order to verify the intent of the rule is benign.
If this change was not planned, inspect the other actions taken by this actor.",
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
                    name="Workspace Admin Creates Default Routing Rule",
                    expect_match=True,
                    data=sample_logs.workspace_admin_creates_default_routing_rule
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Deletes Default Routing Rule",
                    expect_match=True,
                    data=sample_logs.workspace_admin_deletes_default_routing_rule
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