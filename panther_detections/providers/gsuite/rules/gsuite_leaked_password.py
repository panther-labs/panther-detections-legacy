import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_leaked_password(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a user's password has been compromised, so they disabled the account."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Password Leaked",
        rule_id="GSuite.LeakedPassword",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Credential Access:Unsecured Credentials'],
        ),
        reports={'MITRE ATT&CK': ['TA0006:T1552']},
        severity=detection.SeverityHigh,
        description="GSuite reported a user's password has been compromised, so they disabled the account.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_password_leak",
        runbook="GSuite has already disabled the compromised user's account. Consider investigating how the user's account was compromised, and reset their account and password. Advise the user to change any other passwords in use that are the sae as the compromised password.",
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
                    name="Normal Login Event",
                    expect_match=False,
                    data=sample_logs.normal_login_event
                ),
                detection.JSONUnitTest(
                    name="Account Warning Not For Password Leaked",
                    expect_match=False,
                    data=sample_logs.account_warning_not_for_password_leaked
                ),
                detection.JSONUnitTest(
                    name="Account Warning For Password Leaked",
                    expect_match=True,
                    data=sample_logs.account_warning_for_password_leaked
                ),
                
            ]
        )
    )