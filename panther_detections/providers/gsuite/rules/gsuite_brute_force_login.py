import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_brute_force_login(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was denied login access several times"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="--DEPRECATED-- GSuite Brute Force Login",
        rule_id="GSuite.BruteForceLogin",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityMedium,
        description="A GSuite user was denied login access several times",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login_failure",
        runbook="Analyze the IP they came from and actions taken before/after.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=(overrides.summary_attrs),
        threshold=10,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Failed Login",
                    expect_match=True,
                    data=sample_logs.failed_login
                ),
                detection.JSONUnitTest(
                    name="Successful Login",
                    expect_match=False,
                    data=sample_logs.successful_login
                ),
                detection.JSONUnitTest(
                    name="Other Login Event",
                    expect_match=False,
                    data=sample_logs.other_login_event
                ),
                
            ]
        )
    )