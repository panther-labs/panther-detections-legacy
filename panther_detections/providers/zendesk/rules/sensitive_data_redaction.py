from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import REDACTION_ACTIONS, ZENDESK_CHANGE_DESCRIPTION, rule_tags


def sensitive_data_redaction(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A user updated account setting that disabled credit card redaction."""

    def _title(event: PantherEvent) -> str:
        action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
        return f"User [{event.udm('actor_user')}] {action} credit card redaction"

    def _severity(event: PantherEvent) -> str:
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() != "disabled":
            return "INFO"
        return "HIGH"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Zendesk Credit Card Redaction Off",
        rule_id="Zendesk.SensitiveDataRedactionOff",
        log_types=[schema.LogTypeZendeskAudit],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="A user updated account setting that disabled credit card redaction.",
        tags=rule_tags("Collection:Data from Information Repositories"),
        reports={"MITRE ATT&CK": ["TA0009:T1213"]},
        runbook="Re-enable credit card redaction.",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("source_type", "account_setting"),
            match_filters.deep_equal("source_label", "Credit Card Redaction"),
            match_filters.deep_in("action", REDACTION_ACTIONS),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - Credit Card Redaction Off",
                    expect_match=True,
                    data=sample_logs.zendesk___credit_card_redaction_off,
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Credit Card Redaction On",
                    expect_match=True,
                    data=sample_logs.zendesk___credit_card_redaction_on,
                ),
                detection.JSONUnitTest(
                    name="User assumption settings changed",
                    expect_match=False,
                    data=sample_logs.user_assumption_settings_changed,
                ),
            ]
        ),
    )
