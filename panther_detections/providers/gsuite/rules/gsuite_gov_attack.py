import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_gov_attack(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported that it detected a government backed attack against your account."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Government Backed Attack",
        rule_id="GSuite.GovernmentBackedAttack",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityCritical,
        description="GSuite reported that it detected a government backed attack against your account.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#gov_attack_warning",
        runbook="Followup with GSuite support for more details.",
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
                    name="Government Backed Attack Warning",
                    expect_match=True,
                    data=sample_logs.government_backed_attack_warning
                ),
                
            ]
        )
    )