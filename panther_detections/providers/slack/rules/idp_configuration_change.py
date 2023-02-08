import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["idp_configuration_change"]


def idp_configuration_change(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to the identity provider (IdP) configuration for Slack organizations."""
    # from panther_base_helpers import slack_alert_context
    # IDP_CHANGE_ACTIONS = {
    #    "idp_configuration_added": "Slack IDP Configuration Added",
    #    "idp_configuration_deleted": "Slack IDP Configuration Deleted",
    #    "idp_prod_configuration_updated": "Slack IDP Configuration Updated",
    # }

    # def _title(event: PantherEvent) -> str:
    #    if event.get("action") in IDP_CHANGE_ACTIONS:
    #        return IDP_CHANGE_ACTIONS.get(event.get("action"))
    #    return "Slack IDP Configuration Changed"

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack IDP Configuration Changed",
        rule_id="Slack.AuditLogs.IDPConfigurationChanged",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityHigh,
        description="Detects changes to the identity provider (IdP) configuration for Slack organizations.",
        tags=["Slack"],
        # reports=,
        reference="https://api.slack.com/admins/audit-logs",
        # runbook=,
        alert_title=_title,
        summary_attrs=["action", "p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    return event.get("action") in IDP_CHANGE_ACTIONS
        ],
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
