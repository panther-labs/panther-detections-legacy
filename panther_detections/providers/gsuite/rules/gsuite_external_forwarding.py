import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_external_forwarding(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has configured mail forwarding to an external domain"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Gsuite Mail forwarded to external domain",
        rule_id="GSuite.ExternalMailForwarding",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Collection:Email Collection'],
        ),
        reports={'MITRE ATT&CK': ['TA0009:T1114']},
        severity=detection.SeverityHigh,
        description="A user has configured mail forwarding to an external domain",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#email_forwarding_out_of_domain",
        runbook="Follow up with user to remove this forwarding rule if not allowed.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['p_any_emails']
        ,
        threshold="",
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Forwarding to External Address",
                    expect_match=True,
                    data=sample_logs.forwarding_to_external_address
                ),
                detection.JSONUnitTest(
                    name="Forwarding to External Address - Allowed Domain",
                    expect_match=False,
                    data=sample_logs.forwarding_to_external_address___allowed_domain
                ),
                detection.JSONUnitTest(
                    name="Non Forwarding Event",
                    expect_match=False,
                    data=sample_logs.non_forwarding_event
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )