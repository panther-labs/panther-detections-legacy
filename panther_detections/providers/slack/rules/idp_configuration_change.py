import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["idp_configuration_change"]
__all__ = ["idp_configuration_change"]


def idp_configuration_change(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to the identity provider (IdP) configuration for Slack organizations."""

    IDP_CHANGE_ACTIONS = {
        "idp_configuration_added": "Slack IDP Configuration Added",
        "idp_configuration_deleted": "Slack IDP Configuration Deleted",
        "idp_prod_configuration_updated": "Slack IDP Configuration Updated",
    }

    def _title(event: PantherEvent) -> str:
        if event.get("action") in IDP_CHANGE_ACTIONS:
            return IDP_CHANGE_ACTIONS.get(event.get("action"))
        return "Slack IDP Configuration Changed"

    return detection.Rule(
        overrides=overrides,
        name="Slack IDP Configuration Changed",
        rule_id="Slack.AuditLogs.IDPConfigurationChanged",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityHigh,
        description="Detects changes to the identity provider (IdP) configuration for Slack organizations.",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        alert_title=_title,
        summary_attrs=["action", "p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_in("action", IDP_CHANGE_ACTIONS)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="IDP Configuration Added",
                    expect_match=True,
                    data=sample_logs.idp_configuration_change_idp_configuration_added,
                ),
                detection.JSONUnitTest(
                    name="IDP Configuration Deleted",
                    expect_match=True,
                    data=sample_logs.idp_configuration_change_idp_configuration_deleted,
                ),
                detection.JSONUnitTest(
                    name="IDP Configuration Updated",
                    expect_match=True,
                    data=sample_logs.idp_configuration_change_idp_configuration_updated,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.idp_configuration_change_user_logout
                ),
            ]
        ),
    )
