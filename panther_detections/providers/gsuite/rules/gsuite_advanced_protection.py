import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_advanced_protection(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user disabled advanced protection for themselves."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Advanced Protection Change",
        rule_id="GSuite.AdvancedProtection",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite', 'Defense Evasion:Impair Defenses'],
        ),
        reports={'MITRE ATT&CK': ['TA0005:T1562']},
        severity=detection.SeverityLow,
        description="A user disabled advanced protection for themselves.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts#titanium_change",
        runbook="Have the user re-enable Google Advanced Protection",
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
                    name="Advanced Protection Enabled",
                    expect_match=False,
                    data=sample_logs.advanced_protection_enabled
                ),
                detection.JSONUnitTest(
                    name="Advanced Protection Disabled",
                    expect_match=True,
                    data=sample_logs.advanced_protection_disabled
                ),
                
            ]
        )
    )