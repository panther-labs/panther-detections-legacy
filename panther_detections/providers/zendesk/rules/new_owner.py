import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import ZENDESK_CHANGE_DESCRIPTION


def new_owner(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Only one admin user can be the account owner. Ensure the change in ownership is expected."""
    import re

    ZENDESK_OWNER_CHANGED = re.compile(r"Owner changed from (?P<old_owner>.+) to (?P<new_owner>[^$]+)", re.IGNORECASE)

    def _title(event: PantherEvent) -> str:
        old_owner = "<UNKNOWN_USER>"
        new_owner = "<UNKNOWN_USER>"
        matches = ZENDESK_OWNER_CHANGED.match(event.get(ZENDESK_CHANGE_DESCRIPTION, ""))
        if matches:
            old_owner = matches.group("old_owner")
            new_owner = matches.group("new_owner")
        return f"zendesk administrative owner changed from {old_owner} to {new_owner}"

    def _filter(event: PantherEvent) -> bool:
        return event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("owner changed from ")

    return detection.Rule(
        overrides=overrides,
        name="Zendesk Account Owner Changed",
        rule_id="Zendesk.AccountOwnerChanged",
        log_types=["Zendesk.Audit"],
        severity=detection.SeverityHigh,
        description="Only one admin user can be the account owner. Ensure the change in ownership is expected.",
        tags=["Zendesk", "Privilege Escalation:Valid Accounts"],
        reports={"MITRE ATT&CK": ["TA0004:T1078"]},
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        # threshold=,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
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
