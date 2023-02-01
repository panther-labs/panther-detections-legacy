import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["user_suspended"]


def user_suspended(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was suspended, the account may have been compromised by a spam network."""

    def rule_filter() -> detection.PythonFilter:
        def _rule(event: PantherEvent) -> bool:
            USER_SUSPENDED_EVENTS = {
                "account_disabled_generic",
                "account_disabled_spamming_through_relay",
                "account_disabled_spamming",
                "account_disabled_hijacked",
            }
            # this is a filter now
            # if deep_get(event, "id", "applicationName") != "login":
            #     return False
            return bool(event.get("name") in USER_SUSPENDED_EVENTS)

        return detection.PythonFilter(func=_rule)

    def _title(event: PantherEvent) -> str:
        user = event["parameters"]["affected_email_address"]
        if not user:
            user = "<UNKNOWN_USER>"
        return f"User [{user}]'s account was disabled"

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite User Suspended",
        rule_id="GSuite.UserSuspended",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityHigh,
        description="A GSuite user was suspended, the account may have been compromised by a spam network.",
        tags=["GSuite"],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_generic",
        runbook="Investigate the behavior that got the account suspended. Verify with the user that this intended behavior. If not, the account may have been compromised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            # the path needs to use dot notation as seen in this unit test: https://github.com/panther-labs/panther-utils/blob/main/tests/test_match_filters.py#L22
            match_filters.deep_equal("id.applicationName", "login"),
            rule_filter(),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Login Event", expect_match=False, data=sample_logs.user_suspended_normal_login_event
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
