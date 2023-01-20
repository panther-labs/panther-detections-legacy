import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_two_step_verification(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user disabled two step verification for themselves."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Two Step Verification Change",
        rule_id="GSuite.TwoStepVerification",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Defense Evasion:Modify Authentication Process'],
        ),
        reports={'MITRE ATT&CK': ['TA0005:T1556']},
        severity=detection.SeverityLow,
        description="A user disabled two step verification for themselves.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts",
        runbook="Depending on company policy, either suggest or require the user re-enable two step verification.",
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
                    name="Two Step Verification Enabled",
                    expect_match=False,
                    data=sample_logs.two_step_verification_enabled
                ),
                detection.JSONUnitTest(
                    name="Two Step Verification Disabled",
                    expect_match=True,
                    data=sample_logs.two_step_verification_disabled
                ),
                
            ]
        )
    )