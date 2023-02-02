import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import deserialize_administrator_log_event_description, duo_alert_context

__all__ = ["admin_user_mfa_bypass_enabled"]


def admin_user_mfa_bypass_enabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """An Administrator enabled a user to authenticate without MFA."""

    def _title(event: PantherEvent) -> str:
        return (
            f"Duo: [{event.get('username', '<username_not_found>')}] "
            f"updated account [{event.get('object', '<object_not_found>')}] "
            "to not require two-factor authentication."
        )

    def _filter(event: PantherEvent) -> bool:
        from panther_detections.providers.duo._shared import (
            deserialize_administrator_log_event_description,
        )

        if event.get("action") == "user_update":
            description = deserialize_administrator_log_event_description(event)
            if "status" in description:
                return description.get("status") == "Bypass"
        return False

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin User MFA Bypass Enabled",
        rule_id="Duo.Admin.User.MFA.Bypass.Enabled",
        log_types=["Duo.Administrator"],
        severity=detection.SeverityMedium,
        description="An Administrator enabled a user to authenticate without MFA.",
        alert_title=_title,
        threshold=1,
        alert_context=duo_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Account Active",
                    expect_match=False,
                    data=sample_logs.admin_user_mfa_bypass_enabled_account_active,
                ),
                detection.JSONUnitTest(
                    name="Account Disabled",
                    expect_match=False,
                    data=sample_logs.admin_user_mfa_bypass_enabled_account_disabled,
                ),
                detection.JSONUnitTest(
                    name="Bypass Enabled",
                    expect_match=True,
                    data=sample_logs.admin_user_mfa_bypass_enabled_bypass_enabled,
                ),
                detection.JSONUnitTest(
                    name="Phones Update",
                    expect_match=False,
                    data=sample_logs.admin_user_mfa_bypass_enabled_phones_update,
                ),
            ]
        ),
    )
