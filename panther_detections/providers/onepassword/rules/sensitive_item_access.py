import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SHARED_SUMMARY_ATTRS,
    ITEM_USAGE_LOG_TYPE,
    SENSITIVE_ITEM_WATCHLIST,
    create_item_usage_alert_context,
    rule_tags,
)

__all__ = ["sensitive_item_access"]


def sensitive_item_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Alerts when a user defined list of sensitive items in 1Password is accessed"""

    def _title(event: PantherEvent) -> str:
        return f"A Sensitive 1Password Item was Accessed by user {event.deep_get('user', 'name')}"

    return detection.Rule(
        overrides=overrides,
        name="Sensitive 1Password Item Accessed",
        rule_id="OnePassword.Sensitive.Item",
        log_types=[ITEM_USAGE_LOG_TYPE],
        tags=rule_tags("Credential Access:Unsecured Credentials", "Configuration Required"),
        reports={detection.ReportKeyMITRE: ["TA0006:T1552"]},
        severity=detection.SeverityLow,
        description="Alerts when a user defined list of sensitive items in 1Password is accessed",
        reference="https://1password.com/downloads/",
        runbook="Contact Admin to ensure this was sanctioned activity",
        filters=(pre_filters or []) + [match_filters.deep_in("item_uuid", SENSITIVE_ITEM_WATCHLIST)],
        alert_title=_title,
        alert_context=create_item_usage_alert_context,
        summary_attrs=SHARED_SUMMARY_ATTRS,
        unit_tests=[
            detection.JSONUnitTest(
                name="1Password - Sensitive Item Accessed",
                expect_match=True,
                data=sample_logs.sensitive_item_accessed,
            ),
            detection.JSONUnitTest(
                name="1Password - Regular Item Usage",
                expect_match=False,
                data=sample_logs.regular_item_usage,
            ),
        ],
    )
