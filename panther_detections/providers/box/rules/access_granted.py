import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs

def access_granted(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user granted access to their box account to Box technical support from account settings."""

    def _title(event: PantherEvent) -> str:
       return (
           f"User [{event.deep_get('created_by', 'name', default='<UNKNOWN_USER>')}] granted "
           f"access to their account"
       )

    return detection.Rule(
        overrides=overrides,
        name="Box Access Granted",
        rule_id="Box.Access.Granted",
        log_types=['Box.Event'],
        severity=detection.SeverityLow,
        description="A user granted access to their box account to Box technical support from account settings.",
        tags=['Box'],
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Investigate whether the user purposefully granted access to their account.",
        alert_title=_title,
        summary_attrs=['p_any_ip_addresses'],
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("event_type", "ACCESS_GRANTED")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Regular Event",
                    expect_match=False,
                    data=sample_logs.regular_event
                ),
                detection.JSONUnitTest(
                    name="Access Granted",
                    expect_match=True,
                    data=sample_logs.access_granted
                ),
                
            ]
        )
    )