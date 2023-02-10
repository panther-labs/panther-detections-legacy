from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["user_suspended"]


def user_suspended(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was suspended, the account may have been compromised by a spam network."""

    def _title(event: PantherEvent) -> str:
        user = event["parameters"]["affected_email_address"]
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite User Suspended",
        rule_id="GSuite.UserSuspended",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityHigh,
        description="A GSuite user was suspended, the account may have been compromised by a spam network.",
        tags=rule_tags(),
        # reports=,
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_generic",
        runbook="Investigate the behavior that got the account suspended. Verify with the user that this"
        "was intended behavior. If not, the account may have been compromised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "login"),
            match_filters.deep_in(
                "name",
                {
                    "account_disabled_generic",
                    "account_disabled_spamming_through_relay",
                    "account_disabled_spamming",
                    "account_disabled_hijacked",
                },
            ),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Login Event",
                    expect_match=False,
                    data=sample_logs.user_suspended_normal_login_event,
                ),
                detection.JSONUnitTest(
                    name="Account Warning Not For User Suspended",
                    expect_match=False,
                    data=sample_logs.user_suspended_account_warning_not_for_user_suspended,
                ),
                detection.JSONUnitTest(
                    name="Account Warning For Suspended User",
                    expect_match=True,
                    data=sample_logs.user_suspended_account_warning_for_suspended_user,
                ),
            ]
        ),
    )
