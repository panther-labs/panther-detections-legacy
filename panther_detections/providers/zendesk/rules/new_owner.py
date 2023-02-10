from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import ZENDESK_CHANGE_DESCRIPTION, ZENDESK_OWNER_CHANGED, rule_tags


def new_owner(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Only one admin user can be the account owner. Ensure the change in ownership is expected."""

    def _title(event: PantherEvent) -> str:
        owner_old = "<UNKNOWN_USER>"
        owner_new = "<UNKNOWN_USER>"
        matches = ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
        if matches:
            owner_old = matches.group("old_owner")
            owner_new = matches.group("new_owner")
        return f"zendesk administrative owner changed from {owner_old} to {owner_new}"

    def _filter(event: PantherEvent) -> bool:
        return event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("owner changed from ")

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Zendesk Account Owner Changed",
        rule_id="Zendesk.AccountOwnerChanged",
        log_types=[schema.LogTypeZendeskAudit],
        severity=detection.SeverityHigh,
        description="Only one admin user can be the account owner. Ensure the change in ownership is expected.",
        tags=rule_tags("Privilege Escalation:Valid Accounts"),
        reports={"MITRE ATT&CK": ["TA0004:T1078"]},
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("action", "update"),
            match_filters.deep_equal("source_type", "account"),
            detection.PythonFilter(func=_filter),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - Owner Changed", expect_match=True, data=sample_logs.zendesk___owner_changed
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Admin Role Assigned",
                    expect_match=False,
                    data=sample_logs.zendesk___admin_role_assigned,
                ),
            ]
        ),
    )
