import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     SYSTEM_LOG_TYPE,
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

<<<<<<< HEAD:panther_detections/providers/duo/rules/duo_admin_sso_saml_requirement_disabled.py

def duo_admin_sso_saml_requirement_disabled(
=======
def admin_sso_saml_requirement_disabled(
>>>>>>> d529fd4 (initial duo tests):panther_detections/providers/duo/rules/admin_sso_saml_requirement_disabled.py
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when SAML Authentication for Administrators is marked as Disabled or Optional."""

    # def _title(event: PantherEvent) -> str:
    #
    #     return "The title of the alert"

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin SSO SAML Requirement Disabled",
        rule_id="Duo.Admin.SSO.SAML.Requirement.Disabled",
        log_types=["Duo.Administrator"],
        # tags=(overrides.tags),
        # reports="",
        severity=detection.SeverityMedium,
        description="Detects when SAML Authentication for Administrators is marked as Disabled or Optional.",
        # reference="",
        # runbook="",
        filters=(pre_filters or [])
        + [
            # filters
        ],
        alert_title=_title,
        # summary_attrs=(overrides.summary_attrs),
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Enforcement Disabled", expect_match=True, data=sample_logs.enforcement_disabled
                ),
                detection.JSONUnitTest(
                    name="Enforcement Optional", expect_match=True, data=sample_logs.enforcement_optional
                ),
                detection.JSONUnitTest(
                    name="Enforcement Required", expect_match=False, data=sample_logs.enforcement_required
                ),
                detection.JSONUnitTest(name="SSO Update", expect_match=False, data=sample_logs.sso_update),
            ]
        ),
        # alert_context=,
        # alert_grouping=
        # destinations=
        # enabled=
    )
