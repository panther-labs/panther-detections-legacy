import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_mobile_device_screen_unlock_fail(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Someone failed to unlock a user's device multiple times in quick succession."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Device Unlock Failures",
        rule_id="GSuite.DeviceUnlockFailure",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Credential Access:Brute Force'],
        ),
        reports={'MITRE ATT&CK': ['TA0006:T1110']},
        severity=detection.SeverityMedium,
        description="Someone failed to unlock a user's device multiple times in quick succession.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#FAILED_PASSWORD_ATTEMPTS_EVENT",
        runbook="Verify that these unlock attempts came from the user, and not a malicious actor which has acquired the user's device.",
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
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.normal_mobile_event
                ),
                detection.JSONUnitTest(
                    name="Small Number of Failed Logins",
                    expect_match=False,
                    data=sample_logs.small_number_of_failed_logins
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with int Type",
                    expect_match=True,
                    data=sample_logs.multiple_failed_login_attempts_with_int_type
                ),
                detection.JSONUnitTest(
                    name="Multiple Failed Login Attempts with String Type",
                    expect_match=True,
                    data=sample_logs.multiple_failed_login_attempts_with_string_type
                ),
                
            ]
        )
    )