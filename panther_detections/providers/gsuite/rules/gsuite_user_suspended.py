import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_user_suspended(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was suspended, the account may have been compromised by a spam network."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Suspended",
        rule_id="GSuite.UserSuspended",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityHigh,
        description="A GSuite user was suspended, the account may have been compromised by a spam network.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_generic",
        runbook="Investigate the behavior that got the account suspended. Verify with the user that this intended behavior. If not, the account may have been compromised.",
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
                    name="Account Warning Not For User Suspended",
                    expect_match=False,
                    data=sample_logs.account_warning_not_for_user_suspended
                ),
                detection.JSONUnitTest(
                    name="Account Warning For Suspended User",
                    expect_match=True,
                    data=sample_logs.account_warning_for_suspended_user
                ),
                
            ]
        )
    )