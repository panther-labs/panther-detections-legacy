import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_login_type(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A login of a non-approved type was detected for this user."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Login Type",
        rule_id="GSuite.LoginType",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Configuration Required', 'Initial Access:Valid Accounts'],
        ),
        reports={'MITRE ATT&CK': ['TA0001:T1078']},
        severity=detection.SeverityMedium,
        description="A login of a non-approved type was detected for this user.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login",
        runbook="Correct the user account settings so that only logins of approved types are available.",
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
                    name="Login With Approved Type",
                    expect_match=False,
                    data=sample_logs.login_with_approved_type
                ),
                detection.JSONUnitTest(
                    name="Login With Unapproved Type",
                    expect_match=True,
                    data=sample_logs.login_with_unapproved_type
                ),
                detection.JSONUnitTest(
                    name="Non-Login event",
                    expect_match=False,
                    data=sample_logs.non_login_event
                ),
                detection.JSONUnitTest(
                    name="Saml Login Event",
                    expect_match=False,
                    data=sample_logs.saml_login_event
                ),
                
            ]
        )
    )