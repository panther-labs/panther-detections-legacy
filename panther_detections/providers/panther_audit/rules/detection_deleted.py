import typing
from panther_sdk import PantherEvent, detection, schema
from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import PANTHER_DETECTION_DELETE_ACTIONS

__all__ = ["detection_deleted"]


def detection_deleted(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detection content has been removed from Panther."""

    def _title(event: PantherEvent) -> str:
        return f"Detection Content has been deleted by {event.deep_get('actor', 'name')}"

    def _alert_context(event: PantherEvent) -> typing.Dict[str, typing.Any]:
        detections_list = event.deep_get("actionParams", "input", "detections")
        return {
            "deleted_detections_list": [x.get("id") for x in detections_list],
            "user": event.get("actor"),
            "ip": event.get("source_ip"),
        }

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Detection content has been deleted from Panther",
        rule_id="Panther.Detection.Deleted",
        log_types=[schema.LogTypePantherAudit],
        severity=detection.SeverityInfo,
        description="Detection content has been removed from Panther.",
        tags=["DataModel", "Defense Evasion:Impair Defenses"],
        reports={"MITRE ATT&CK": ["TA0005:T1562"]},
        runbook="Ensure this change was approved and appropriate.",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_context=_alert_context,
        filters=[
            match_filters.deep_in("actionName", PANTHER_DETECTION_DELETE_ACTIONS),
            match_filters.deep_equal("actionResult", "SUCCEEDED"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Delete 1 Detection",
                    expect_match=True,
                    data=sample_logs.detection_deleted_delete_1_detection
                ),
                detection.JSONUnitTest(
                    name="Delete Many Detections",
                    expect_match=True,
                    data=sample_logs.detection_deleted_delete_many_detections,
                ),
                detection.JSONUnitTest(
                    name="Non-Delete event",
                    expect_match=False,
                    data=sample_logs.detection_deleted_non_delete_event,
                ),
            ]
        ),
    )
