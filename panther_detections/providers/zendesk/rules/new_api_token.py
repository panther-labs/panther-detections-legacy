from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def new_api_token(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A user created a new API token to be used with Zendesk."""
    API_TOKEN_ACTIONS = [
        "create",
        "destroy",
    ]

    def _title(event: PantherEvent) -> str:
        action = event.get("action", "<UNKNOWN_ACTION>")
        return f"[{event.get('p_log_type')}]: User [{event.udm('actor_user')}] {action} an api token"

    def _severity(event: PantherEvent) -> str:
        if event.get("action", "") == "destroy":
            return "INFO"
        return "HIGH"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Zendesk API Token Created",
        rule_id="Zendesk.NewAPIToken",
        log_types=["Zendesk.Audit"],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="A user created a new API token to be used with Zendesk.",
        tags=["Zendesk", "Credential Access:Steal Application Access Token"],
        reports={"MITRE ATT&CK": ["TA0006:T1528"]},
        runbook="Validate the api token was created for valid use case, otherwise delete the token immediately.",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("source_type", "api_token"),
            match_filters.deep_in("action", API_TOKEN_ACTIONS),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - API Token Updated", expect_match=False, data=sample_logs.zendesk___api_token_updated
                ),
                detection.JSONUnitTest(
                    name="Zendesk - API Token Created", expect_match=True, data=sample_logs.zendesk___api_token_created
                ),
            ]
        ),
    )
