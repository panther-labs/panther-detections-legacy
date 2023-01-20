import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_mobile_device_compromise(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a user's device has been compromised."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Device Compromised",
        rule_id="GSuite.DeviceCompromise",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityMedium,
        description="GSuite reported a user's device has been compromised.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#DEVICE_COMPROMISED_EVENT",
        runbook="Have the user change their passwords and reset the device.",
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
                    name="Suspicious Activity Shows not Compromised",
                    expect_match=False,
                    data=sample_logs.suspicious_activity_shows_not_compromised
                ),
                detection.JSONUnitTest(
                    name="Suspicious Activity Shows Compromised",
                    expect_match=True,
                    data=sample_logs.suspicious_activity_shows_compromised
                ),
                
            ]
        )
    )