from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters, standard_tags

from .. import sample_logs

__all__ = ["gov_attack"]


def gov_attack(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite reported that it detected a government backed attack against your account."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}] may have been "
            f"targeted by a government attack"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="GSuite Government Backed Attack",
        rule_id="GSuite.GovernmentBackedAttack",
        log_types=schema.LogTypeGSuiteActivityEvent,
        tags=standard_tags.IDENTITY_AND_ACCESS_MGMT,  # Check this
        severity=detection.SeverityCritical,
        description="GSuite reported that it detected a government backed attack against your account.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#gov_attack_warning",
        runbook="Follow up with GSuite support for more details.",
        filters=[
            # name == change_calendars_acls &
            # parameters.grantee_email == __public_principal__@public.calendar.google.com
            match_filters.deep_equal("name", "gov_attack_warning")
        ],
        alert_title=_title,
        unit_tests=[
            detection.JSONUnitTest(
                name="Gov backed warning",
                expect_match=True,
                data=sample_logs.gov_backed_warning,
            ),
            detection.JSONUnitTest(
                name="Normal login",
                expect_match=False,
                data=sample_logs.normal_login,
            ),
        ],
    )
