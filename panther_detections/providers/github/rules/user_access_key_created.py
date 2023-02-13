import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["user_access_key_created"]


def user_access_key_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a GitHub user access key is created."""

    # def _title(event: PantherEvent) -> str:
    #    return f"User [{event.udm('actor_user')}] created a new ssh key"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub User Access Key Created",
        rule_id="GitHub.User.AccessKeyCreated",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityInfo,
        description="Detects when a GitHub user access key is created.",
        tags=["GitHub", "Persistence:Valid Accounts"],
        reports={"MITRE ATT&CK": ["TA0003:T1078"]},
        # reference=,
        # runbook=,
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            # def rule(event):
            #    return event.get("action") == "public_key.create"
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - User Access Key Created",
                    expect_match=True,
                    data=sample_logs.user_access_key_created_github___user_access_key_created,
                ),
                detection.JSONUnitTest(
                    name="GitHub - User Access Key Deleted",
                    expect_match=False,
                    data=sample_logs.user_access_key_created_github___user_access_key_deleted,
                ),
            ]
        ),
    )
