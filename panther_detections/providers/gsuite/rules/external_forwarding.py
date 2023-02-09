import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

__all__ = ["external_forwarding"]


def external_forwarding(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has configured mail forwarding to an external domain"""

    def check_allowed_domain(
        allowed_domains: typing.List[str],
    ) -> detection.PythonFilter:
        def _check_allowed_domain(event: PantherEvent) -> bool:
            # todo: create helper in _shared
            domain = event.deep_get("parameters", "email_forwarding_destination_address").split("@")[-1]
            # todo: can this be refactored using match_filters
            if domain not in allowed_domains:
                return True
            return False

        return detection.PythonFilter(func=_check_allowed_domain)

    def _title(event: PantherEvent) -> str:
        external_address = event.deep_get("parameters", "email_forwarding_destination_address")
        user = event.deep_get("actor", "email")
        return f"An email forwarding rule was created by {user} to {external_address}"

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="Gsuite Mail forwarded to external domain",
        rule_id="GSuite.ExternalMailForwarding",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityHigh,
        description="A user has configured mail forwarding to an external domain",
        tags=["GSuite", "Collection:Email Collection", "Configuration Required"],
        reports={"MITRE ATT&CK": ["TA0009:T1114"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#email_forwarding_out_of_domain",
        runbook="Follow up with user to remove this forwarding rule if not allowed.",
        alert_title=_title,
        summary_attrs=["p_any_emails"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "user_accounts"),
            match_filters.deep_equal("name", "email_forwarding_out_of_domain"),
            check_allowed_domain(["example.com"]),
        ],
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
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.external_forwarding_listobject_type,
                ),
            ]
        ),
    )
