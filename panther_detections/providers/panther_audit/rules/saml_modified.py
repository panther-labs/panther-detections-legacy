import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["saml_modified"]


def saml_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """An Admin has modified Panther's SAML configuration."""

    def _title(event: PantherEvent) -> str:
        return f"Panther SAML config has been modified by {event.deep_get('actor', 'name')}"

    def _alert_context(event: PantherEvent) -> typing.Dict[str, typing.Any]:
        return {
            "user": event.deep_get("actor", "name"),
            "ip": event.get("sourceIP"),
        }

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Panther SAML configuration has been modified",
        rule_id="Panther.SAML.Modified",
        log_types=[schema.LogTypePantherAudit],
        severity=detection.SeverityHigh,
        description="An Admin has modified Panther's SAML configuration.",
        tags=["DataModel", "Defense Evasion:Impair Defenses"],
        reports={"MITRE ATT&CK": ["TA0005:T1562"]},
        runbook="Ensure this change was approved and appropriate.",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses", "p_any_usernames"],
        alert_context=_alert_context,
        filters=[
            match_filters.deep_equal("actionName", "UPDATE_SAML_SETTINGS"),
            match_filters.deep_equal("actionResult", "SUCCEEDED"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="SAML config modified",
                    expect_match=True,
                    data=sample_logs.saml_modified_saml_config_modified,
                ),
                detection.JSONUnitTest(
                    name="SAML config viewed",
                    expect_match=False,
                    data=sample_logs.saml_modified_saml_config_viewed,
                ),
            ]
        ),
    )
