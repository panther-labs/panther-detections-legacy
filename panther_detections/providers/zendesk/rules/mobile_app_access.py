from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import MOBILE_APP_ACTIONS, ZENDESK_CHANGE_DESCRIPTION, rule_tags


def mobile_app_access(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A user updated account setting that enabled or disabled mobile app access."""

    def _title(event: PantherEvent) -> str:
        action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
        return f"User [{event.udm('actor_user')}] {action} mobile app access"

    def _severity(event: PantherEvent) -> str:
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
            return "INFO"
        return "MEDIUM"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Zendesk Mobile App Access Modified",
        rule_id="Zendesk.MobileAppAccessUpdated",
        log_types=[schema.LogTypeZendeskAudit],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityMedium),
        description="A user updated account setting that enabled or disabled mobile app access.",
        tags=rule_tags("Persistence:Valid Accounts"),
        reports={"MITRE ATT&CK": ["TA0003:T1078"]},
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("source_type", "account_setting"),
            match_filters.deep_equal("source_label", "Zendesk Support Mobile App Access"),
            match_filters.deep_in("action", MOBILE_APP_ACTIONS),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - Mobile App Access Off",
                    expect_match=True,
                    data=sample_logs.zendesk___mobile_app_access_off,
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Mobile App Access On",
                    expect_match=True,
                    data=sample_logs.zendesk___mobile_app_access_on,
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Credit Card Redaction",
                    expect_match=False,
                    data=sample_logs.zendesk___credit_card_redaction,
                ),
            ]
        ),
    )
