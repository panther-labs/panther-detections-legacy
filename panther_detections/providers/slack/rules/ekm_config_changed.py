import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["ekm_config_changed"]


def ekm_config_changed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when the logging settings for a workspace's EKM configuration has changed"""
    # from panther_base_helpers import slack_alert_context

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    # TODO: Add details to the context
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack EKM Config Changed",
        rule_id="Slack.AuditLogs.EKMConfigChanged",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityHigh,
        description="Detects when the logging settings for a workspace's EKM configuration has changed",
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
            #    # Only alert on the `ekm_logging_config_set` action
            #    return event.get("action") == "ekm_logging_config_set"
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="EKM Config Changed", expect_match=True, data=sample_logs.ekm_config_changed_ekm_config_changed
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.ekm_config_changed_user_logout
                ),
            ]
        ),
    )
