import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SHARED_SUMMARY_ATTRS,
    SYSTEM_LOG_TYPE,
    CLIENT_ALLOWLIST,
    create_unusual_client_alert_context,
    rule_tags
    )

__all__ = [
    "unusual_client"
]


def unusual_client(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when unusual or undesirable 1Password clients access your 1Password account"""

    def _title(event: PantherEvent) -> str:
        return f"Unusual 1Password client - {event.deep_get('client', 'app_name')} detected"

    return detection.Rule(
        overrides=overrides,
        name="Unusual 1Password Client Detected",
        rule_id="OnePassword.Unusual.Client",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            "Credential Access:Credentials from Password Stores",
        ),
        reports={detection.ReportKeyMITRE: ["TA0006:T1555"]},
        severity=detection.SeverityMedium,
        description="Detects when unusual or undesirable 1Password clients access your 1Password account",
        reference="https://1password.com/downloads/",
        runbook="Contact Admin to ensure this was sanctioned activity",
        filters=(pre_filters or [])
        + [
            match_filters.deep_not_in("client.app_name", CLIENT_ALLOWLIST)
        ],
        alert_title=_title,
        alert_context=create_unusual_client_alert_context,
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

