from panther_sdk import PantherEvent, detection, schema

from .. import sample_logs
from .._shared import (
    deserialize_administrator_log_event_description,
    duo_alert_context,
    rule_tags,
)

__all__ = ["admin_sso_saml_requirement_disabled"]


def admin_sso_saml_requirement_disabled(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when SAML Authentication for Administrators is marked as Disabled or Optional."""

    def _title(event: PantherEvent) -> str:
        description = deserialize_administrator_log_event_description(event)
        return (
            f"Duo: [{event.get('username', '<username_not_found>')}] "
            "changed SAML authentication requirements for Administrators "
            f"to [{description.get('enforcement_status', '<enforcement_status_not_found>')}]"
        )

    def _filter(event: PantherEvent) -> bool:
        from panther_detections.providers.duo._shared import (  # pylint: disable=W0621
            deserialize_administrator_log_event_description,
        )

        if event.get("action") == "admin_single_sign_on_update":
            description = deserialize_administrator_log_event_description(event)
            enforcement_status = description.get("enforcement_status", "required")
            return enforcement_status != "required"
        return False

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo Admin SSO SAML Requirement Disabled",
        rule_id="Duo.Admin.SSO.SAML.Requirement.Disabled",
        log_types=[schema.LogTypeDuoAdministrator],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="Detects when SAML Authentication for Administrators is marked as Disabled or Optional.",
        alert_title=_title,
        threshold=1,
        alert_context=duo_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Enforcement Disabled",
                    expect_match=True,
                    data=sample_logs.admin_sso_saml_requirement_disabled_enforcement_disabled,
                ),
                detection.JSONUnitTest(
                    name="Enforcement Optional",
                    expect_match=True,
                    data=sample_logs.admin_sso_saml_requirement_disabled_enforcement_optional,
                ),
                detection.JSONUnitTest(
                    name="Enforcement Required",
                    expect_match=False,
                    data=sample_logs.admin_sso_saml_requirement_disabled_enforcement_required,
                ),
                detection.JSONUnitTest(
                    name="SSO Update",
                    expect_match=False,
                    data=sample_logs.admin_sso_saml_requirement_disabled_sso_update,
                ),
            ]
        ),
    )
