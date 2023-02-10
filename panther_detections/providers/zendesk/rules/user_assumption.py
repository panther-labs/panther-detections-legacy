from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs


def user_assumption(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """User enabled or disabled zendesk support user assumption."""
    USER_SUSPENSION_ACTIONS = [
        "create",
        "update",
    ]

    def _title(event: PantherEvent) -> str:
        return f"A user [{event.udm('actor_user')}] updated zendesk support user assumption settings"

    def _source_label_filter(event: PantherEvent) -> bool:
        # admin roles have their own handling
        return event.get("source_label", "").lower() in {"account assumption", "assumption duration"}

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Enabled Zendesk Support to Assume Users",
        rule_id="Zendesk.UserAssumption",
        log_types=[schema.LogTypeZendeskAudit],
        severity=detection.SeverityMedium,
        description="User enabled or disabled zendesk support user assumption.",
        tags=["Zendesk", "Lateral Movement:Use Alternate Authentication Material"],
        reports={"MITRE ATT&CK": ["TA0008:T1550"]},
        runbook="Investigate whether allowing zendesk support to assume users is necessary. If not, disable the feature.",
        alert_title=_title,
        summary_attrs=["p_any_addresses"],
        filters=[
            match_filters.deep_equal("source_type", "account_setting"),
            match_filters.deep_in("action", USER_SUSPENSION_ACTIONS),
            detection.PythonFilter(func=_source_label_filter),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User assumption settings changed",
                    expect_match=True,
                    data=sample_logs.user_assumption_settings_changed,
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Credit Card Redaction On",
                    expect_match=False,
                    data=sample_logs.zendesk___credit_card_redaction_on,
                ),
            ]
        ),
    )
