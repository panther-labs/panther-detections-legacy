import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import SYSTEM_LOG_TYPE, create_alert_context, rule_tags


def user_logged_in_as_user(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Reports when an Atlassian user logs in (impersonates) another user."""

    def _title(event: PantherEvent) -> str:
        actor = event.deep_get("attributes", "actor", "email", default="<unknown-email>")
        context = event.deep_get("attributes", "context", default=[{}])
        impersonated_user = context[0].get("attributes", {}).get("email", "<unknown-email>")
        return f"{actor} logged in as {impersonated_user}."

    return detection.Rule(
        overrides=overrides,
        name="Atlassian user logged in as user",
        rule_id="Atlassian.User.LoggedInAsUser",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(),
        severity=detection.SeverityHigh,
        description="Reports when an Atlassian user logs in (impersonates) another user.",
        reference="https://support.atlassian.com/user-management/docs/log-in-as-another-user/",
        runbook="Validate that the Atlassian admin did log in (impersonate) as another user.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("attributes.action", "user_logged_in_as_user"),
        ],
        alert_title=_title,
        alert_context=create_alert_context,
        unit_tests=[
            detection.JSONUnitTest(
                name="MFA Disabled",
                expect_match=True,
                data=sample_logs.admin_impersonated_user_successfully,
            ),
            detection.JSONUnitTest(
                name="Login Event",
                expect_match=False,
                data=sample_logs.user_logged_in_as_user_not_in_log,
            ),
        ],
    )
