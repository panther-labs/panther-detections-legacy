import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["legal_hold_policy_modified"]


def legal_hold_policy_modified(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects changes to configured legal hold policies"""
    # from panther_base_helpers import deep_get, slack_alert_context
    # LEGAL_HOLD_POLICY_ACTIONS = {
    #    "legal_hold_policy_entities_deleted": "Slack Legal Hold Policy Entities Deleted",
    #    "legal_hold_policy_exclusion_added": "Slack Exclusions Added to Legal Hold Policy",
    #    "legal_hold_policy_released": "Slack Legal Hold Released",
    #    "legal_hold_policy_updated": "Slack Legal Hold Updated",
    # }

    # def _title(event: PantherEvent) -> str:
    #    # Only the `legal_hold_policy_updated` event includes relevant data to deduplicate
    #    if event.get("action") == "legal_hold_policy_updated":
    #        return (
    #            f"Slack Legal Hold Updated "
    #            f"[{deep_get(event, 'details', 'old_legal_hold_policy', 'name')}]"
    #        )
    #    if event.get("action") in LEGAL_HOLD_POLICY_ACTIONS:
    #        return LEGAL_HOLD_POLICY_ACTIONS.get(event.get("action"))
    #    return "Slack Legal Hold Policy Modified"

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Slack Legal Hold Policy Modified",
        rule_id="Slack.AuditLogs.LegalHoldPolicyModified",
        log_types=["Slack.AuditLogs"],
        severity=detection.SeverityHigh,
        description="Detects changes to configured legal hold policies",
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
            #    return event.get("action") in LEGAL_HOLD_POLICY_ACTIONS
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Legal Hold - Entities Deleted",
                    expect_match=True,
                    data=sample_logs.legal_hold_policy_modified_legal_hold___entities_deleted,
                ),
                detection.JSONUnitTest(
                    name="Legal Hold - Exclusions Added",
                    expect_match=True,
                    data=sample_logs.legal_hold_policy_modified_legal_hold___exclusions_added,
                ),
                detection.JSONUnitTest(
                    name="Legal Hold - Policy Released",
                    expect_match=True,
                    data=sample_logs.legal_hold_policy_modified_legal_hold___policy_released,
                ),
                detection.JSONUnitTest(
                    name="Legal Hold - Policy Updated",
                    expect_match=True,
                    data=sample_logs.legal_hold_policy_modified_legal_hold___policy_updated,
                ),
                detection.JSONUnitTest(
                    name="User Logout", expect_match=False, data=sample_logs.legal_hold_policy_modified_user_logout
                ),
            ]
        ),
    )
