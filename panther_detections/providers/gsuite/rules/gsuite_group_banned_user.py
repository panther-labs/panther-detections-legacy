import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_group_banned_user(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was banned from an enterprise group by moderator action."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite User Banned from Group",
        rule_id="GSuite.GroupBannedUser",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityLow,
        description="A GSuite user was banned from an enterprise group by moderator action.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/groups-enterprise#ban_user_with_moderation",
        runbook="Investigate the banned user to see if further disciplinary action needs to be taken.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['actor:email']
        ,
        threshold="",
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User Added",
                    expect_match=False,
                    data=sample_logs.user_added
                ),
                detection.JSONUnitTest(
                    name="User Banned from Group",
                    expect_match=True,
                    data=sample_logs.user_banned_from_group
                ),
                
            ]
        )
    )