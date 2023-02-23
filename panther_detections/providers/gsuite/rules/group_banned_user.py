from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["group_banned_user"]


def group_banned_user(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was banned from an enterprise group by moderator action."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}] "
            f"banned another user from a group."
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite User Banned from Group",
        rule_id="GSuite.GroupBannedUser",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityLow,
        description="A GSuite user was banned from an enterprise group by moderator action.",
        tags=rule_tags(),
        # reports=,
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups-enterprise#ban_user_with_moderation",
        runbook="Investigate the banned user to see if further disciplinary action needs to be taken.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "groups_enterprise"),
            match_filters.deep_equal("type", "moderator_action"),
            match_filters.deep_equal("name", "ban_user_with_moderation"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User Added",
                    expect_match=False,
                    data=sample_logs.group_banned_user_user_added,
                ),
                detection.JSONUnitTest(
                    name="User Banned from Group",
                    expect_match=True,
                    data=sample_logs.group_banned_user_user_banned_from_group,
                ),
            ]
        ),
    )
