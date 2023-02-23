from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["doc_ownership_transfer"]


def doc_ownership_transfer(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite document's ownership was transferred to an external party."""

    def _check_in_domain(event: PantherEvent) -> bool:
        org_domains = {
            "@example.com",
        }
        new_owner = event.deep_get("parameters", "NEW_VALUE")
        return bool(new_owner) and not any(new_owner.endswith(x) for x in org_domains)

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        enabled=False,
        name="GSuite Document External Ownership Transfer",
        rule_id="GSuite.DocOwnershipTransfer",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityLow,
        description="A GSuite document's ownership was transferred to an external party.",
        tags=rule_tags("Configuration Required", "Collection:Data from Information Repositories"),
        reports={"MITRE ATT&CK": ["TA0009:T1213"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-docs-settings#TRANSFER_DOCUMENT_OWNERSHIP",
        runbook="Verify that this document did not contain sensitive or private company information.",
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "admin"),
            match_filters.deep_equal("name", "TRANSFER_DOCUMENT_OWNERSHIP"),
            detection.PythonFilter(func=_check_in_domain),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Ownership Transferred Within Organization",
                    expect_match=False,
                    data=sample_logs.doc_ownership_transfer_ownership_transferred_within_organization,
                ),
                detection.JSONUnitTest(
                    name="Document Transferred to External User",
                    expect_match=True,
                    data=sample_logs.doc_ownership_transfer_document_transferred_to_external_user,
                ),
            ]
        ),
    )
