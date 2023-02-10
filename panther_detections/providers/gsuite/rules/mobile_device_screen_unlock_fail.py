from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

__all__ = ["mobile_device_screen_unlock_fail"]


def mobile_device_screen_unlock_fail(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Someone failed to unlock a user's device multiple times in quick succession."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
            f"'s device had multiple failed unlock attempts"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite User Device Unlock Failures",
        rule_id="GSuite.DeviceUnlockFailure",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="Someone failed to unlock a user's device multiple times in quick succession.",
        tags=["GSuite", "Credential Access:Brute Force"],
        reports={"MITRE ATT&CK": ["TA0006:T1110"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#FAILED_PASSWORD_ATTEMPTS_EVENT",
        runbook="Verify that these unlock attempts came from the user,"
        "and not a malicious actor which has acquired the user's device.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "mobile"),
            match_filters.deep_equal("name", "FAILED_PASSWORD_ATTEMPTS_EVENT"),
            match_filters.deep_greater_than(float("parameters.FAILED_PASSWD_ATTEMPTS"), 10),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.mobile_device_screen_unlock_fail_normal_mobile_event,
                ),
                detection.JSONUnitTest(
                    name="Small Number of Failed Logins",
                    expect_match=False,
                    data=sample_logs.mobile_device_screen_unlock_fail_small_number_of_failed_logins,
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with int Type",
                    expect_match=True,
                    data=sample_logs.mobile_device_screen_unlock_fail_multiple_failed_login_attempts_with_int_type,
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with String Type",
                    expect_match=True,
                    data=sample_logs.mobile_device_screen_unlock_fail_multiple_failed_login_attempts_with_string_type,
                ),
            ]
        ),
    )