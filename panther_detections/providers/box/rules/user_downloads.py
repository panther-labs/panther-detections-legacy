import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs


def user_downloads(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has exceeded the threshold for number of downloads within a single time frame."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('created_by', 'login', default='<UNKNOWN_USER>')}] "
            f"exceeded threshold for number of downloads in the configured time frame."
        )

    return detection.Rule(
        overrides=overrides,
        name="Box Large Number of Downloads",
        rule_id="Box.Large.Number.Downloads",
        log_types=["Box.Event"],
        severity=detection.SeverityLow,
        description="A user has exceeded the threshold for number of downloads within a single time frame.",
        tags=["Box", "Exfiltration:Exfiltration Over Web Service"],
        reports={"MITRE ATT&CK": ["TA0010:T1567"]},
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Investigate whether this user's download activity is expected.  Investigate the cause of this download activity.",
        alert_title=_title,
        summary_attrs=["ip_address"],
        threshold=100,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("event_type", "DOWNLOAD")],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Regular Event", expect_match=False, data=sample_logs.regular_event),
                detection.JSONUnitTest(name="User Download", expect_match=True, data=sample_logs.user_download),
            ]
        ),
    )
