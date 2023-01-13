import typing

from panther_core import PantherEvent
from panther_sdk import detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SHARED_SUMMARY_ATTRS,
    SYSTEM_LOG_TYPE,
    create_alert_context,
    rule_tags,
)

__all__ = [
    "api_key_created",
    "api_key_revoked",
]


def api_key_created(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user created an API Key in Okta"""

    def _title(event: PantherEvent) -> str:
        target = event.get("target", [{}])
        key_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else "MISSING TARGET"

        return (
            f"{event.deep_get('actor', 'displayName')} <{event.deep_get('actor', 'alternateId')}>"
            f"created a new API key - <{key_name}>"
        )

    return detection.Rule(
        overrides=overrides,
        name="Okta API Key Created",
        rule_id="Okta.APIKeyCreated",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            "Credential Access:Steal Application Access Token",
        ),
        reports={detection.ReportKeyMITRE: ["TA0006:T1528"]},
        severity=detection.SeverityInfo,
        description="A user created an API Key in Okta",
        reference="https://help.okta.com/en/prod/Content/Topics/Security/API.htm",
        runbook="Reach out to the user if needed to validate the activity.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("eventType", "system.api_token.create"),
            match_filters.deep_equal("outcome.result", "SUCCESS"),
        ],
        alert_title=_title,
        alert_context=create_alert_context,
        summary_attrs=SHARED_SUMMARY_ATTRS,
        unit_tests=[
            detection.JSONUnitTest(
                name="API Key Created",
                expect_match=True,
                data=sample_logs.system_api_token_create,
            ),
        ],
    )


def api_key_revoked(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has revoked an API Key in Okta"""

    def _title(event: PantherEvent) -> str:
        target = event.get("target", [{}])
        key_name = target[0].get("displayName", "MISSING DISPLAY NAME") if target else "MISSING TARGET"

        return (
            f"{event.get('actor', {}).get('displayName')} <{event.get('actor', {}).get('alternateId')}>"
            f"revoked API key - <{key_name}>"
        )

    return detection.Rule(
        overrides=overrides,
        name="Okta API Key Revoked",
        rule_id="Okta.APIKeyRevoked",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(),
        severity=detection.SeverityInfo,
        description="A user has revoked an API Key in Okta",
        reference="https://help.okta.com/en/prod/Content/Topics/Security/API.htm",
        runbook="Validate this action was authorized.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("eventType", "system.api_token.revoke"),
            match_filters.deep_equal("outcome.result", "SUCCESS"),
        ],
        alert_title=_title,
        alert_context=create_alert_context,
        summary_attrs=SHARED_SUMMARY_ATTRS,
        unit_tests=[
            detection.JSONUnitTest(
                name="API Key Revoked",
                expect_match=True,
                data=sample_logs.system_api_token_revoke,
            ),
        ],
    )
