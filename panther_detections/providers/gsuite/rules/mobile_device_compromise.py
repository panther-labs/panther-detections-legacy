from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["mobile_device_compromise"]


def mobile_device_compromise(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a user's device has been compromised."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('parameters', 'USER_EMAIL', default='<UNKNOWN_USER>')}]'s "
            f"device was compromised"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite User Device Compromised",
        rule_id="GSuite.DeviceCompromise",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="GSuite reported a user's device has been compromised.",
        tags=rule_tags(),
        # reports=,
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#DEVICE_COMPROMISED_EVENT",
        runbook="Have the user change their passwords and reset the device.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "mobile"),
            match_filters.deep_equal("name", "DEVICE_COMPROMISED_EVENT"),
            match_filters.deep_equal("parameters.DEVICE_COMPROMISED_STATE", "COMPROMISED"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.mobile_device_compromise_normal_mobile_event,
                ),
                detection.JSONUnitTest(
                    name="Suspicious Activity Shows not Compromised",
                    expect_match=False,
                    data=sample_logs.mobile_device_compromise_suspicious_activity_shows_not_compromised,
                ),
                detection.JSONUnitTest(
                    name="Suspicious Activity Shows Compromised",
                    expect_match=True,
                    data=sample_logs.mobile_device_compromise_suspicious_activity_shows_compromised,
                ),
            ]
        ),
    )