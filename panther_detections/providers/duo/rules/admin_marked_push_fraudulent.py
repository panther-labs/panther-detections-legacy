from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
    rule_tags,
)


def admin_marked_push_fraudulent(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Duo push was marked fraudulent by an admin."""

    def _title(event: PantherEvent) -> str:

        event_description = deserialize_administrator_log_event_description(event)
        admin_username = event.get("username", "Unknown")
        user_email = event_description.get("email", "Unknown")

        return f"Duo Admin [{admin_username}] denied due to an anomalous 2FA push for [{user_email}]"

    def _filter(event: PantherEvent) -> bool:
        from panther_detections.providers.duo._shared import (  # pylint: disable=W0621
            deserialize_administrator_log_event_description,
        )

        event_description = deserialize_administrator_log_event_description(event)
        return "fraudulent" in event_description.get("error", "").lower()

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo Admin Marked Push Fraudulent",
        rule_id="DUO.Admin.Action.MarkedFraudulent",
        log_types=[schema.LogTypeDuoAdministrator],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="A Duo push was marked fraudulent by an admin.",
        reference="https://duo.com/docs/adminapi#administrator-logs",
        runbook="Follow up with the administrator to determine reasoning for marking fraud.",
        filters=[
            match_filters.deep_equal("action", "admin_2fa_error"),
            detection.PythonFilter(func=_filter),
        ],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="marked_fraud", expect_match=True, data=sample_logs.admin_marked_push_fraudulent_marked_fraud
                ),
                detection.JSONUnitTest(
                    name="different_admin_action",
                    expect_match=False,
                    data=sample_logs.admin_marked_push_fraudulent_different_admin_action,
                ),
            ]
        ),
        alert_context=duo_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
    )
