import typing

from panther_sdk import detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["mfa_settings_changed"]
__all__ = ["mfa_settings_changed"]


def mfa_settings_changed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to Multi-Factor Authentication requirements"""

    return detection.Rule(
        overrides=overrides,
        name="Slack MFA Settings Changed",
        rule_id="Slack.AuditLogs.MFASettingsChanged",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityHigh,
        description="Detects changes to Multi-Factor Authentication requirements",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "pref.two_factor_auth_changed")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="MFA Auth Changed", expect_match=True, data=sample_logs.mfa_settings_changed_mfa_auth_changed
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.mfa_settings_changed_user_logout
                ),
            ]
        ),
    )
