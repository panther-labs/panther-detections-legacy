import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def mobile_device_compromise(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a user's device has been compromised."""
    #from panther_base_helpers import deep_get

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"User [{deep_get(event, 'parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s "
    #        f"device was compromised"
    #    )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite User Device Compromised",
        rule_id="GSuite.DeviceCompromise",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityMedium,
        description="GSuite reported a user's device has been compromised.",
        tags=['GSuite'],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#DEVICE_COMPROMISED_EVENT",
        runbook="Have the user change their passwords and reset the device.",
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    if deep_get(event, "id", "applicationName") != "mobile":
            #        return False
            #    if event.get("name") == "DEVICE_COMPROMISED_EVENT":
            #        return bool(deep_get(event, "parameters", "DEVICE_COMPROMISED_STATE") == "COMPROMISED")
            #    return False

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.mobile_device_compromise_normal_mobile_event
                ),
                detection.JSONUnitTest(
                    name="Suspicious Activity Shows not Compromised",
                    expect_match=False,
                    data=sample_logs.mobile_device_compromise_suspicious_activity_shows_not_compromised
                ),
                detection.JSONUnitTest(
                    name="Suspicious Activity Shows Compromised",
                    expect_match=True,
                    data=sample_logs.mobile_device_compromise_suspicious_activity_shows_compromised
                ),

            ]
        )
    )
