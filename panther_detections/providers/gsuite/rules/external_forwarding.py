import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["external_forwarding"]


def external_forwarding(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has configured mail forwarding to an external domain"""

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get

            # List of external domains that are allowed to be forwarded to
            ALLOWED_DOMAINS = ["example.com"]
            if event.get("name") == "email_forwarding_out_of_domain":
                domain = deep_get(event, "parameters", "email_forwarding_destination_address").split("@")[-1]
                if domain not in ALLOWED_DOMAINS:
                    return True
            return False

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        external_address = event.deep_get("parameters", "email_forwarding_destination_address")
        user = event.deep_get("actor", "email")
        return f"An email forwarding rule was created by {user} to {external_address}"

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="Gsuite Mail forwarded to external domain",
        rule_id="GSuite.ExternalMailForwarding",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityHigh,
        description="A user has configured mail forwarding to an external domain",
        tags=["GSuite", "Collection:Email Collection", "Configuration Required"],
        reports={"MITRE ATT&CK": ["TA0009:T1114"]},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#email_forwarding_out_of_domain",
        runbook="Follow up with user to remove this forwarding rule if not allowed.",
        alert_title=_title,
        summary_attrs=["p_any_emails"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or []) + [match_filters.deep_equal("id.applicationName", "user_accounts"), rule_filter()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Forwarding to External Address",
                    expect_match=True,
                    data=sample_logs.external_forwarding_forwarding_to_external_address,
                ),
                detection.JSONUnitTest(
                    name="Forwarding to External Address - Allowed Domain",
                    expect_match=False,
                    data=sample_logs.external_forwarding_forwarding_to_external_address___allowed_domain,
                ),
                detection.JSONUnitTest(
                    name="Non Forwarding Event",
                    expect_match=False,
                    data=sample_logs.external_forwarding_non_forwarding_event,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type", expect_match=False, data=sample_logs.external_forwarding_listobject_type
                ),
            ]
        ),
    )
