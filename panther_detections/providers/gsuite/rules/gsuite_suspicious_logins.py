import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_suspicious_logins(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a suspicious login for this user."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Suspicious GSuite Login",
        rule_id="GSuite.SuspiciousLogins",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityMedium,
        description="GSuite reported a suspicious login for this user.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#suspicious_login",
        runbook="Checkout the details of the login and verify this behavior with the user to ensure the account wasn't compromised.",
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
                    name="Account Warning Not For Suspicious Login",
                    expect_match=False,
                    data=sample_logs.account_warning_not_for_suspicious_login
                ),
                detection.JSONUnitTest(
                    name="Account Warning For Suspicious Login",
                    expect_match=True,
                    data=sample_logs.account_warning_for_suspicious_login
                ),
                
            ]
        )
    )