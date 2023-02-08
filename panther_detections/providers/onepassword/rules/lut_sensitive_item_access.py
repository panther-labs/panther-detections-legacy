import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    CLIENT_ALLOWLIST,
    ITEM_USAGE_LOG_TYPE,
    SHARED_SUMMARY_ATTRS,
    create_item_usage_alert_context,
    rule_tags,
)

__all__ = ["lut_sensitive_item_access"]


def lut_sensitive_item_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Alerts when a user defined list of sensitive items in 1Password is accessed"""

    def _title(event: PantherEvent) -> str:
        return f"Unusual 1Password client - {event.deep_get('client', 'app_name')} detected"

    return detection.Rule(
        overrides=overrides,
        name="BETA - Sensitive 1Password Item Accessed",
        rule_id="OnePassword.Lut.Sensitive.Item",
        log_types=[ITEM_USAGE_LOG_TYPE],
        tags=rule_tags("Credential Access:Unsecured Credentials", "BETA", "Lookup Table", "Configuration Required"),
        reports={detection.ReportKeyMITRE: ["TA0006:T1552"]},
        severity=detection.SeverityLow,
        description="Alerts when a user defined list of sensitive items in 1Password is accessed",
        reference="",
        runbook="",
        filters=(pre_filters or []) + [match_filters.deep_not_in("client.app_name", CLIENT_ALLOWLIST)],
        alert_title=_title,
        alert_context=create_item_usage_alert_context,
        summary_attrs=SHARED_SUMMARY_ATTRS,
        unit_tests=[
            detection.JSONUnitTest(
                name="1Password - Expected Client",
                expect_match=False,
                data=sample_logs.expected_client,
            ),
            detection.JSONUnitTest(
                name="1Password - Bad Client",
                expect_match=True,
                data=sample_logs.bad_client,
            ),
        ],
    )
