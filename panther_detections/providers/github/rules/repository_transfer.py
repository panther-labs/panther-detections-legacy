import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["repository_transfer"]


def repository_transfer(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A user accepted a request to receive a transferred Github repository, a  Github repository was transferred to another repository network, or a user sent a request to transfer a repository to another user or organization."""
    # from panther_base_helpers import github_alert_context

    # def _title(event: PantherEvent) -> str:
    #    # (Optional) Return a string which will be shown as the alert title.
    #    # If no 'dedup' function is defined, the return value of this method
    #    # will act as deduplication string.
    #    action = event.get("action", "")
    #    if action == "repo.transfer":
    #        # return something like: A user accepted a request to receive a transferred repository.
    #        return (
    #            f"Github User [{event.get('actor','NO_ACTOR_FOUND')}] accepted a request to "
    #            f"receive repository [{event.get('repo','NO_REPO_NAME_FOUND')}] in "
    #            f"[{event.get('org','NO_ORG_NAME_FOUND')}]."
    #        )
    #    if action == "repo.transfer_outgoing":
    #        # return something like: A repository was transferred to another repository network.
    #        return (
    #            f"Github User [{event.get('actor','NO_ACTOR_FOUND')}] transferred repository "
    #            f"[{event.get('repo','NO_REPO_NAME_FOUND')}] in "
    #            f"[{event.get('org','NO_ORG_NAME_FOUND')}]."
    #        )
    #    if action == "repo.transfer_start":
    #        # return something like: A user sent a request to transfer a
    #        # repository to another user or organization.
    #        return (
    #            f"Github User [{event.get('actor','NO_ACTOR_FOUND')}] sent a request to "
    #            f"transfer repository [{event.get('repo','NO_REPO_NAME_FOUND')}] "
    #            f"to another user or organization."
    #        )
    #    return ""

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    #  (Optional) Return a dictionary with additional data to be included in the alert
    #    # sent to the SNS/SQS/Webhook destination
    #    return github_alert_context(event)

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="Github Repository Transfer",
        rule_id="Github.Repository.Transfer",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.SeverityMedium,
        description="A user accepted a request to receive a transferred Github repository, a  Github repository was transferred to another repository network, or a user sent a request to transfer a repository to another user or organization.",
        tags=["Github Repository", "Github Repository Transfer", "Repository", "Transfer"],
        # reports=,
        reference="https://docs.github.com/en/enterprise-server@3.3/repositories/creating-and-managing-repositories/transferring-a-repository"
        "https://docs.github.com/en/enterprise-cloud@latest/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise#repo-category-actions",
        runbook="Please check with the referenced users or their supervisors to ensure the transferring of this repository is expected and allowed.",
        alert_title=_title,
        summary_attrs=["action"],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            # def rule(event):
            #    # Return True to match the log event and trigger an alert.
            #    return event.get("action", "") in (
            #        "repo.transfer",
            #        "repo.transfer_outgoing",
            #        "repo.transfer_start",
            #    )
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Public Repo Created",
                    expect_match=False,
                    data=sample_logs.repository_transfer_public_repo_created,
                ),
                detection.JSONUnitTest(
                    name="Repo Transfer Outgoing",
                    expect_match=True,
                    data=sample_logs.repository_transfer_repo_transfer_outgoing,
                ),
                detection.JSONUnitTest(
                    name="Repo Transfer Start",
                    expect_match=True,
                    data=sample_logs.repository_transfer_repo_transfer_start,
                ),
                detection.JSONUnitTest(
                    name="Repository Transfer",
                    expect_match=True,
                    data=sample_logs.repository_transfer_repository_transfer,
                ),
            ]
        ),
    )
