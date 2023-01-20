import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_doc_ownership_transfer(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite document's ownership was transferred to an external party."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Document External Ownership Transfer",
        rule_id="GSuite.DocOwnershipTransfer",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Configuration Required', 'Collection:Data from Information Repositories'],
        ),
        reports={'MITRE ATT&CK': ['TA0009:T1213']},
        severity=detection.SeverityLow,
        description="A GSuite document's ownership was transferred to an external party.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-docs-settings#TRANSFER_DOCUMENT_OWNERSHIP",
        runbook="Verify that this document did not contain sensitive or private company information.",
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
                    name="Ownership Transferred Within Organization",
                    expect_match=False,
                    data=sample_logs.ownership_transferred_within_organization
                ),
                detection.JSONUnitTest(
                    name="Document Transferred to External User",
                    expect_match=True,
                    data=sample_logs.document_transferred_to_external_user
                ),
                
            ]
        )
    )