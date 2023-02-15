from panther_sdk import PantherEvent, detection, schema

from .. import sample_logs
from .._shared import duo_alert_context, rule_tags

__all__ = ["admin_new_admin_api_app_integration"]


def admin_new_admin_api_app_integration(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Identifies creation of new Admin API integrations for Duo."""

    def _title(event: PantherEvent) -> str:
        return (
            f"Duo: [{event.get('username', '<username_not_found>')}] "
            "created a new Admin API integration "
            f"to [{event.get('object', '<object_not_found>')}]"
        )

    def _filter(event: PantherEvent) -> bool:
        from panther_detections.providers.duo._shared import (  # pylint: disable=W0621
            deserialize_administrator_log_event_description,
        )

        if event.get("action") == "integration_create":
            description = deserialize_administrator_log_event_description(event)
            integration_type = description.get("type")
            return integration_type == "Admin API"
        return False

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo Admin New Admin API App Integration",
        rule_id="Duo.Admin.New.Admin.API.App.Integration",
        log_types=[schema.LogTypeDuoAdministrator],
        tags=rule_tags(),
        severity=detection.SeverityHigh,
        description="Identifies creation of new Admin API integrations for Duo.",
        alert_title=_title,
        threshold=1,
        alert_context=duo_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin API Integration Created",
                    expect_match=True,
                    data=sample_logs.admin_new_admin_api_app_integration_admin_api_integration_created,
                ),
                detection.JSONUnitTest(
                    name="Non Admin API Integration",
                    expect_match=False,
                    data=sample_logs.admin_new_admin_api_app_integration_non_admin_api_integration,
                ),
                detection.JSONUnitTest(
                    name="Other Event",
                    expect_match=False,
                    data=sample_logs.admin_new_admin_api_app_integration_other_event,
                ),
            ]
        ),
    )
