import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs


def untrusted_device(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user attempted to login from an untrusted device."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] "
            f"attempted to login from an untrusted device."
        )

    return detection.Rule(
        overrides=overrides,
        name="Box Untrusted Device Login",
        rule_id="Box.Untrusted.Device",
        log_types=["Box.Event"],
        severity=detection.SeverityInfo,
        description="A user attempted to login from an untrusted device.",
        tags=["Box", "Initial Access:Valid Accounts"],
        reports={"MITRE ATT&CK": ["TA0001:T1078"]},
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Investigate whether this is a valid user attempting to login to box.",
        alert_title=_title,
        summary_attrs=["ip_address"],
        filters=(pre_filters or [])
        + [
            # DEVICE_TRUST_CHECK_FAILED
            #  detect when a user attempts to login from an untrusted device
            match_filters.deep_equal("event_type", "DEVICE_TRUST_CHECK_FAILED")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Regular Event", expect_match=False, data=sample_logs.regular_event),
                detection.JSONUnitTest(name="New Login Event", expect_match=True, data=sample_logs.new_login_event),
            ]
        ),
    )