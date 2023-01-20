import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_mobile_device_suspicious_activity(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a suspicious activity on a user's device."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Device Suspicious Activity",
        rule_id="GSuite.DeviceSuspiciousActivity",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityLow,
        description="GSuite reported a suspicious activity on a user's device.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#SUSPICIOUS_ACTIVITY_EVENT",
        runbook="Validate that the suspicious activity was expected by the user.",
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
                    name="Suspicious Activity",
                    expect_match=True,
                    data=sample_logs.suspicious_activity
                ),
                
            ]
        )
    )