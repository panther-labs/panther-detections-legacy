import typing

from panther_sdk import detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["intune_mdm_disabled"]
__all__ = ["intune_mdm_disabled"]


def intune_mdm_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects the disabling of Microsoft Intune Enterprise MDM within Slack"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Intune MDM Disabled",
        rule_id="Slack.AuditLogs.IntuneMDMDisabled",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityCritical,
        description="Detects the disabling of Microsoft Intune Enterprise MDM within Slack",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "intune_disabled")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Intune Disabled", expect_match=True, data=sample_logs.intune_mdm_disabled_intune_disabled
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.intune_mdm_disabled_user_logout
                ),
            ]
        ),
    )
