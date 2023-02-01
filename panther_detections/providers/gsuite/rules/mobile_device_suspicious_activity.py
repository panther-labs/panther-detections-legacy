import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["mobile_device_suspicious_activity"]


def mobile_device_suspicious_activity(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported a suspicious activity on a user's device."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}]" f"'s device was compromised"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Device Suspicious Activity",
        rule_id="GSuite.DeviceSuspiciousActivity",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityLow,
        description="GSuite reported a suspicious activity on a user's device.",
        tags=["GSuite"],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/mobile#SUSPICIOUS_ACTIVITY_EVENT",
        runbook="Validate that the suspicious activity was expected by the user.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "mobile"),
            match_filters.deep_equal("name", "SUSPICIOUS_ACTIVITY_EVENT"),
            # def rule(event):
            #    if deep_get(event, "id", "applicationName") != "mobile":
            #        return False
            #    return bool(event.get("name") == "SUSPICIOUS_ACTIVITY_EVENT")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Mobile Event",
                    expect_match=False,
                    data=sample_logs.mobile_device_suspicious_activity_normal_mobile_event,
                ),
                detection.JSONUnitTest(
                    name="Suspicious Activity",
                    expect_match=True,
                    data=sample_logs.mobile_device_suspicious_activity_suspicious_activity,
                ),
            ]
        ),
    )
