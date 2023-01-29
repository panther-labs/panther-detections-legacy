import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    ZENDESK_CHANGE_DESCRIPTION
)

def mobile_app_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user updated account setting that enabled or disabled mobile app access."""
        #from panther_base_helpers import ZENDESK_CHANGE_DESCRIPTION
    MOBILE_APP_ACTIONS = ["create", "update"]

    def _title(event: PantherEvent) -> str:
       action = event.get(ZENDESK_CHANGE_DESCRIPTION, "<UNKNOWN_ACTION>")
       return f"User [{event.udm('actor_user')}] {action} mobile app access"

    def _severity(event: PantherEvent) -> str:
       if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
           return "INFO"
       return "MEDIUM"

    return detection.Rule(
        overrides=overrides,
        name="Zendesk Mobile App Access Modified",
        rule_id="Zendesk.MobileAppAccessUpdated",
        log_types=['Zendesk.Audit'],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityMedium),
        description="A user updated account setting that enabled or disabled mobile app access.",
        tags=['Zendesk', 'Persistence:Valid Accounts'],
        reports={'MITRE ATT&CK': ['TA0003:T1078']},
        alert_title=_title,
        summary_attrs=['p_any_ip_addresses'],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("source_type", "account_setting"),
            match_filters.deep_equal("source_label", "Zendesk Support Mobile App Access"),
            match_filters.deep_in("action", MOBILE_APP_ACTIONS)
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - Mobile App Access Off",
                    expect_match=True,
                    data=sample_logs.zendesk___mobile_app_access_off
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Mobile App Access On",
                    expect_match=True,
                    data=sample_logs.zendesk___mobile_app_access_on
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Credit Card Redaction",
                    expect_match=False,
                    data=sample_logs.zendesk___credit_card_redaction
                ),
                
            ]
        )
    )