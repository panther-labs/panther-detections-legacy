import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["advanced_protection"]


def advanced_protection(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user disabled advanced protection for themselves."""

    def _title(event: PantherEvent) -> str:
        return (
            f"Advanced protection was disabled for user "
            f"[{event.deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        name="GSuite User Advanced Protection Change",
        rule_id="GSuite.AdvancedProtection",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityLow,
        description="A user disabled advanced protection for themselves.",
        tags=rule_tags("Defense Evasion:Impair Defenses"),
        reports={"MITRE ATT&CK": ["TA0005:T1562"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts#titanium_change",
        runbook="Have the user re-enable Google Advanced Protection",
        alert_title=_title,
        summary_attrs=["actor:email"],
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "user_accounts"),
            match_filters.deep_equal("name", "titanium_unenroll"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Advanced Protection Enabled",
                    expect_match=False,
                    data=sample_logs.advanced_protection_advanced_protection_enabled,
                ),
                detection.JSONUnitTest(
                    name="Advanced Protection Disabled",
                    expect_match=True,
                    data=sample_logs.advanced_protection_advanced_protection_disabled,
                ),
            ]
        ),
    )
