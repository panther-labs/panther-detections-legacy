import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["repo_collaborator_change"]


def repo_collaborator_change(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a repository collaborator is added or removed."""

    # def _title(event: PantherEvent) -> str:
    #    repo_link = f"https://github.com/{event.get('repo','<UNKNOWN_REPO>')}/settings/access"
    #    action = "added to"
    #    if event.get("action") == "repo.remove_member":
    #        action = "removed from"
    #    return (
    #        f"Repository  collaborator [{event.get('user', '<UNKNOWN_USER>')}] {action} "
    #        f"repository {event.get('repo', '<UNKNOWN_REPO>')}. "
    #        f"View current collaborators here: {repo_link}"
    #    )

    # def _severity(event: PantherEvent) -> str:
    #    if event.get("action") == "repo.remove_member":
    #        return "INFO"
    #    return "MEDIUM"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Repository Visibility Change",
        rule_id="Github.Repo.CollaboratorChange",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityMedium),
        description="Detects when a repository collaborator is added or removed.",
        tags=["GitHub", "Initial Access:Supply Chain Compromise"],
        reports={"MITRE ATT&CK": ["TA0001:T1195"]},
        # reference=,
        runbook="Determine if the new collaborator is authorized to access the repository.",
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            # def rule(event):
            #    return event.get("action") == "repo.add_member" or event.get("action") == "repo.remove_member"
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Collaborator Added",
                    expect_match=True,
                    data=sample_logs.repo_collaborator_change_github___collaborator_added,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Collaborator Removed",
                    expect_match=True,
                    data=sample_logs.repo_collaborator_change_github___collaborator_removed,
                ),
                detection.JSONUnitTest(
                    name="GitHub - Non member action",
                    expect_match=False,
                    data=sample_logs.repo_collaborator_change_github___non_member_action,
                ),
            ]
        ),
    )
