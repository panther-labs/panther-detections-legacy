import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    create_alert_context,
    deserialize_administrator_log_event_description,
)


def admin_marked_push_fraudulent(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Duo push was marked fraudulent by an admin."""

    def _title(event: PantherEvent) -> str:

        event_description = deserialize_administrator_log_event_description(event)
        admin_username = event.get("username", "Unknown")
        user_email = event_description.get("email", "Unknown")

        return f"Duo Admin [{admin_username}] denied due to an anomalous 2FA push for [{user_email}]"

    def _marked_fraud(event: PantherEvent) -> bool:
        print(event)
        event_description = deserialize_administrator_log_event_description(event)
        return "fraudulent" in event_description.get("error", "").lower()

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin Marked Push Fraudulent",
        rule_id="DUO.Admin.Action.MarkedFraudulent",
        log_types=["Duo.Administrator"],
        tags=["Duo"],
        severity=detection.SeverityMedium,
        description="A Duo push was marked fraudulent by an admin.",
        reference="https://duo.com/docs/adminapi#administrator-logs",
        runbook="Follow up with the administrator to determine reasoning for marking fraud.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("action", "admin_2fa_error"),
            # match_filters.deep_equal("error".lower(), "fraudulent"),
            detection.PythonFilter(func=_marked_fraud),
        ],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(name="marked_fraud", expect_match=True, data=sample_logs.marked_fraud),
                detection.JSONUnitTest(
                    name="different_admin_action", expect_match=False, data=sample_logs.different_admin_action
                ),
            ]
        ),
        alert_context=create_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
        # destinations=
        # enabled=
    )
