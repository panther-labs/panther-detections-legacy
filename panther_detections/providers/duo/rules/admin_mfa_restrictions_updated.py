import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import duo_alert_context


def admin_mfa_restrictions_updated(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to allowed MFA factors administrators can use to log into the admin panel."""

    def _title(event: PantherEvent) -> str:

        return "Duo Admin MFA Restrictions Updated " f"by [{event.get('username','<user_not_found>')}]"

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin MFA Restrictions Updated",
        rule_id="Duo.Admin.MFA.Restrictions.Updated",
        log_types=["Duo.Administrator"],
        severity=detection.SeverityMedium,
        description="Detects changes to allowed MFA factors administrators can use to log into the admin panel.",
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "update_admin_factor_restrictions")],
        alert_title=_title,
        threshold=1,
        alert_context=duo_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin MFA Update Event",
                    expect_match=True,
                    data=sample_logs.admin_mfa_restrictions_updated_admin_mfa_update_event
                ),
                detection.JSONUnitTest(
                    name="Login Event",
                    expect_match=False,
                    data=sample_logs.admin_mfa_restrictions_updated_login_event
                ),
                
            ]
        ),
    )
