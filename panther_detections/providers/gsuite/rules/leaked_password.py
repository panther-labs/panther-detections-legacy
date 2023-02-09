import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

__all__ = ["leaked_password"]


def leaked_password(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a user's password has been compromised, so they disabled the account."""

    def _title(event: PantherEvent) -> str:
        user = event.deep_get("parameters", "affected_email_address")
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled due to a password leak"

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite User Password Leaked",
        rule_id="GSuite.LeakedPassword",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityHigh,
        description="GSuite reported a user's password has been compromised, so they disabled the account.",
        tags=["GSuite", "Credential Access:Unsecured Credentials"],
        reports={"MITRE ATT&CK": ["TA0006:T1552"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_password_leak",
        runbook="GSuite has already disabled the compromised user's account."
        "Consider investigating how the user's account was compromised, and reset their account and password."
        "Advise the user to change any other passwords in use that are the sae as the compromised password.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "login"),
            match_filters.deep_equal("type", "account_warning"),
            match_filters.deep_in("name", ["account_disabled_password_leak"]),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Login Event", expect_match=False, data=sample_logs.leaked_password_normal_login_event
                ),
                detection.JSONUnitTest(
                    name="Account Warning Not For Password Leaked",
                    expect_match=False,
                    data=sample_logs.leaked_password_account_warning_not_for_password_leaked,
                ),
                detection.JSONUnitTest(
                    name="Account Warning For Password Leaked",
                    expect_match=True,
                    data=sample_logs.leaked_password_account_warning_for_password_leaked,
                ),
            ]
        ),
    )
