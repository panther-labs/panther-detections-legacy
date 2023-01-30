import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

def event_triggered_externally(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """An external user has triggered a box enterprise event."""
    DOMAINS = [
       "@example.com",
    ]

    def _title(event: PantherEvent) -> str:
       return (
           f"External user [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] "
           f"triggered a box event."
       )
    
    def _filter(event: PantherEvent) -> bool:
        # Check that all events are triggered by internal users
        if event.get("event_type") not in ("FAILED_LOGIN", "SHIELD_ALERT"):
            user = event.get("created_by", {})
            # user id 2 indicates an anonymous user
            if user.get("id", "") == "2":
                return True
            print(user.get("login"))
            return bool(
                user.get("login") and not any(user.get("login", "").endswith(x) for x in DOMAINS)
            )
        return False


    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="Box event triggered by unknown or external user",
        rule_id="Box.Event.Triggered.Externally",
        log_types=['Box.Event'],
        severity=detection.SeverityMedium,
        description="An external user has triggered a box enterprise event.",
        tags=['Box', 'Exfiltration:Exfiltration Over Web Service', 'Configuration Required'],
        reports={'MITRE ATT&CK': ['TA0010:T1567']},
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Investigate whether this user's activity is expected.",
        alert_title=_title,
        summary_attrs=['ip_address'],
        threshold=10,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            detection.PythonFilter(func=_filter)
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Regular Event",
                    expect_match=False,
                    data=sample_logs.event_triggered_externally_regular_event
                ),
                detection.JSONUnitTest(
                    name="Previewed Anonymously",
                    expect_match=True,
                    data=sample_logs.previewed_anonymously
                ),
                detection.JSONUnitTest(
                    name="Missing Created By",
                    expect_match=False,
                    data=sample_logs.missing_created_by
                ),
                
            ]
        )
    )