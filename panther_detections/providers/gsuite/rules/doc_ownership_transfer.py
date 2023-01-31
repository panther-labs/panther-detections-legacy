import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def doc_ownership_transfer(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite document's ownership was transferred to an external party."""
    #from panther_base_helpers import deep_get
    # ORG_DOMAINS = {
    #    "@example.com",
    # }

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="GSuite Document External Ownership Transfer",
        rule_id="GSuite.DocOwnershipTransfer",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityLow,
        description="A GSuite document's ownership was transferred to an external party.",
        tags=['GSuite', 'Configuration Required',
              'Collection:Data from Information Repositories'],
        reports={'MITRE ATT&CK': ['TA0009:T1213']},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-docs-settings#TRANSFER_DOCUMENT_OWNERSHIP",
        runbook="Verify that this document did not contain sensitive or private company information.",
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    if deep_get(event, "id", "applicationName") != "admin":
            #        return False
            #    if bool(event.get("name") == "TRANSFER_DOCUMENT_OWNERSHIP"):
            #        new_owner = deep_get(event, "parameters", "NEW_VALUE", default="<UNKNOWN USER>")
            #        return bool(new_owner) and not any(new_owner.endswith(x) for x in ORG_DOMAINS)
            #    return False

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Ownership Transferred Within Organization",
                    expect_match=False,
                    data=sample_logs.doc_ownership_transfer_ownership_transferred_within_organization
                ),
                detection.JSONUnitTest(
                    name="Document Transferred to External User",
                    expect_match=True,
                    data=sample_logs.doc_ownership_transfer_document_transferred_to_external_user
                ),

            ]
        )
    )
