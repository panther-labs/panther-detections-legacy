import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters, standard_tags

from .. import sample_logs

__all__ = ["mobile_device_screen_unlock_fail"]


def mobile_device_screen_unlock_fail(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Someone failed to unlock a user's device multiple times in quick succession."""
    def rule_filter(max_attempts) -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent, max_attempts) -> bool:
            from panther_detections.utils.legacy_filters import deep_get
            if deep_get(event, "id", "applicationName") != "mobile":
                return False

            if event.get("name") == "FAILED_PASSWORD_ATTEMPTS_EVENT":
                attempts = deep_get(event, "parameters",
                                    "FAILED_PASSWD_ATTEMPTS")
                return int(attempts if attempts else 0) > max_attempts
            return False
        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
            f"'s device had multiple failed unlock attempts"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite User Device Unlock Failures",
        rule_id="GSuite.DeviceUnlockFailure",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityMedium,
        description="Someone failed to unlock a user's device multiple times in quick succession.",
        tags=['GSuite', 'Credential Access:Brute Force'],
        reports={'MITRE ATT&CK': ['TA0006:T1110']},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#FAILED_PASSWORD_ATTEMPTS_EVENT",
        runbook="Verify that these unlock attempts came from the user, and not a malicious actor which has acquired the user's device.",
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
                # match_filters.deep_equal("id.applicationName", "mobile"),
                # match_filters.deep_equal(
                #     "name", "FAILED_PASSWORD_ATTEMPTS_EVENT"),
                # match_filters.deep_greater_than(
                #     float("parameters.FAILED_PASSWD_ATTEMPTS"), 10),
                rule_filter(10)
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.mobile_device_screen_unlock_fail_normal_mobile_event
                ),
                detection.JSONUnitTest(
                    name="Small Number of Failed Logins",
                    expect_match=False,
                    data=sample_logs.mobile_device_screen_unlock_fail_small_number_of_failed_logins
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with int Type",
                    expect_match=True,
                    data=sample_logs.mobile_device_screen_unlock_fail_multiple_failed_login_attempts_with_int_type
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with String Type",
                    expect_match=True,
                    data=sample_logs.mobile_device_screen_unlock_fail_multiple_failed_login_attempts_with_string_type
                ),

            ]
        )
    )
