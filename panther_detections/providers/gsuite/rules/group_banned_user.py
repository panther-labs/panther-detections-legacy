import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["group_banned_user"]


def group_banned_user(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was banned from an enterprise group by moderator action."""

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            if event.get("type") == "moderator_action":
                return bool(event.get("name") == "ban_user_with_moderation")

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}] "
            f"banned another user from a group."
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite User Banned from Group",
        rule_id="GSuite.GroupBannedUser",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityLow,
        description="A GSuite user was banned from an enterprise group by moderator action.",
        tags=["GSuite"],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups-enterprise#ban_user_with_moderation",
        runbook="Investigate the banned user to see if further disciplinary action needs to be taken.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [match_filters.deep_equal("id.applicationName", "groups_enterprise"), rule_filter()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User Added", expect_match=False, data=sample_logs.group_banned_user_user_added
                ),
                detection.JSONUnitTest(
                    name="User Banned from Group",
                    expect_match=True,
                    data=sample_logs.group_banned_user_user_banned_from_group,
                ),
            ]
        ),
    )
