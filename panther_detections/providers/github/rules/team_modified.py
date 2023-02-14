from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["team_modified"]


def team_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a team is modified in some way, such as adding a new team,
    deleting a team, modifying members, or a change in repository control."""

    def _title(event: PantherEvent) -> str:
        action_mappings = {
            "create": "created team",
            "destroy": "deleted team",
            "add_member": f"added member [{event.get('user')}] to team",
            "remove_member": f"removed member [{event.get('user')}] from team",
            "add_repository": f"added repository [{event.get('repo')}] to team",
            "removed_repository": f"removed repository [{event.get('repo')}] from team",
            "change_parent_team": "changed parent team for team",
        }
        action_key = event.get("action").split(".")[1]
        action = action_mappings.get(action_key, event.get("action"))
        team_name = event.get("team") if "team" in event else "<MISSING_TEAM>"
        return f"GitHub.Audit: User [{event.get('actor')}] {action} [{team_name}]"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Team Modified",
        rule_id="GitHub.Team.Modified",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityInfo,
        description="Detects when a team is modified in some way, such as adding a new team,"
        "deleting a team, modifying members, or a change in repository control.",
        tags=rule_tags("Initial Access:Supply Chain Compromise"),
        reports={"MITRE ATT&CK": ["TA0001:T1195"]},
        # reference=,
        # runbook=,
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_starts_with("action", "team"),
            match_filters.deep_in(
                "action",
                (
                    "team.add_member",
                    "team.add_repository",
                    "team.change_parent_team",
                    "team.create",
                    "team.destroy",
                    "team.remove_member",
                    "team.remove_repository",
                ),
            ),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Team Deleted",
                    expect_match=True,
                    data=sample_logs.team_modified_github___team_deleted,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Team Created",
                    expect_match=True,
                    data=sample_logs.team_modified_github___team_created,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Team Add repository",
                    expect_match=True,
                    data=sample_logs.team_modified_github___team_add_repository,
                ),
            ]
        ),
    )
