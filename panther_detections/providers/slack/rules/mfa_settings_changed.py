import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["mfa_settings_changed"]


def mfa_settings_changed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to Multi-Factor Authentication requirements"""
    # from panther_base_helpers import slack_alert_context

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    # TODO: Add details to context
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack MFA Settings Changed",
        rule_id="Slack.AuditLogs.MFASettingsChanged",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityHigh,
        description="Detects changes to Multi-Factor Authentication requirements",
        tags=["Slack"],
        # reports=,
        reference="https://api.slack.com/admins/audit-logs",
        # runbook=,
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    return event.get("action") == "pref.two_factor_auth_changed"
        ],
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
