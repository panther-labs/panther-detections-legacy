import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import deserialize_administrator_log_event_description, duo_alert_context


def admin_create_admin(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A new Duo Administrator was created."""

    def _title(event: PantherEvent) -> str:
        event_description = deserialize_administrator_log_event_description(event)
        return (
            f"Duo: [{event.get('username', '<username_not_found>')}] "
            "created a new admin account: "
            f"[{event_description.get('name', '<name_not_found>')}] "
            f"[{event_description.get('email', '<email_not_found>')}]."
        )

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin Create Admin",
        rule_id="Duo.Admin.Create.Admin",
        log_types=["Duo.Administrator"],
        severity=detection.SeverityHigh,
        description="A new Duo Administrator was created.",
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "admin_create")],
        alert_title=_title,
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Create", expect_match=True, data=sample_logs.admin_create_admin_admin_create
                ),
                detection.JSONUnitTest(
                    name="Other Event", expect_match=False, data=sample_logs.admin_create_admin_other_event
                ),
            ]
        ),
        alert_context=duo_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
    )
