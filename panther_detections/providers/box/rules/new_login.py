import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs

def new_login(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user logged in from a new device."""

    def _title(event: PantherEvent) -> str:
       return (
           f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] "
           f"logged in from a new device."
       )

    return detection.Rule(
        overrides=overrides,
        name="Box New Login",
        rule_id="Box.New.Login",
        log_types=['Box.Event'],
        severity=detection.SeverityInfo,
        description="A user logged in from a new device.",
        tags=['Box', 'Initial Access:Valid Accounts'],
        reports={'MITRE ATT&CK': ['TA0001:T1078']},
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Investigate whether this is a valid user login.",
        alert_title=_title,
        summary_attrs=['ip_address'],
        filters=(pre_filters or [])
        + [
             # ADD_LOGIN_ACTIVITY_DEVICE
            #  detect when a user logs in from a device not previously seen
            match_filters.deep_equal("event_type", "ADD_LOGIN_ACTIVITY_DEVICE")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Regular Event",
                    expect_match=False,
                    data=sample_logs.regular_event
                ),
                detection.JSONUnitTest(
                    name="New Login Event",
                    expect_match=True,
                    data=sample_logs.new_login_new_login_event
                ),
                
            ]
        )
    )