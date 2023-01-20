import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_gmail_enhanced_predelivery_scanning(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Gmail Pre-Delivery Message Scanning Disabled",
        rule_id="GSuite.Workspace.GmailPredeliveryScanningDisabled",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0001:T1566']},
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail.",
        reference="https://support.google.com/a/answer/7380368",
        runbook="Pre-delivery scanning is a feature in Gmail that subjects suspicious emails to additional automated scrutiny by Google.
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
                    name="Workspace Admin Disables Enhanced Pre-Delivery Scanning",
                    expect_match=True,
                    data=sample_logs.workspace_admin_disables_enhanced_pre_delivery_scanning
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