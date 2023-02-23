from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

__all__ = ["login_type"]


def login_type(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A login of a non-approved type was detected for this user."""

    approved_login_types = {
        "exchange",
        "google_password",
        "reauth",
        "saml",
        "unknown",
    }

    approved_application_names = {"saml"}

    def _title(event: PantherEvent) -> str:
        return (
            f"A login attempt of a non-approved type was detected for user "
            f"[{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        enabled=False,
        name="GSuite Login Type",
        rule_id="GSuite.LoginType",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A login of a non-approved type was detected for this user.",
        tags=["GSuite", "Configuration Required", "Initial Access:Valid Accounts"],
        reports={"MITRE ATT&CK": ["TA0001:T1078"]},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login",
        runbook="Correct the user account settings so that only logins of approved types are available.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("type", "login"),
            match_filters.deep_not_equal("name", "logout"),
            match_filters.deep_not_in("parameters.login_type", approved_login_types),
            match_filters.deep_not_in("id.applicationName", approved_application_names),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Login With Approved Type",
                    expect_match=False,
                    data=sample_logs.login_type_login_with_approved_type,
                ),
                detection.JSONUnitTest(
                    name="Login With Unapproved Type",
                    expect_match=True,
                    data=sample_logs.login_type_login_with_unapproved_type,
                ),
                detection.JSONUnitTest(
                    name="Non-Login event",
                    expect_match=False,
                    data=sample_logs.login_type_non_login_event,
                ),
                detection.JSONUnitTest(
                    name="Saml Login Event",
                    expect_match=False,
                    data=sample_logs.login_type_saml_login_event,
                ),
            ]
        ),
    )
