import typing
from panther_sdk import PantherEvent, detection, schema
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = [
    "public_repository_created"
]


def public_repository_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A public Github repository was created."""
        #from panther_base_helpers import github_alert_context

    # def _title(event: PantherEvent) -> str:
    #    # (Optional) Return a string which will be shown as the alert title.
    #    # If no 'dedup' function is defined, the return value of this method
    #    # will act as deduplication string.
    #    return (
    #        f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] "
    #        f"created with public status by Github user [{event.get('actor')}]."
    #    )
    ## 
    
    # def _group_by(event: PantherEvent) -> str:
    ##  (Optional) Return a string which will be used to deduplicate similar alerts.
    ## return ''

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    #  (Optional) Return a dictionary with additional data to be included in the alert
    #    # sent to the SNS/SQS/Webhook destination
    #    return github_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="Github Public Repository Created",
        rule_id="Github.Public.Repository.Created",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityMedium,
        description="A public Github repository was created.",
        tags=['Github Repository', 'Public', 'Repository Created'],
        #reports=,
        #reference=,
        runbook="Confirm this github repository was intended to be created as 'public' versus 'private'.",
        alert_title=_title,
        summary_attrs=['actor', 'repo', 'visibility'],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(group_by=_group_by, period_minutes=60),
        filters=[
            # def rule(event):
    #    # Return True if a public repository was created
    #    return event.get("action", "") == "repo.create" and event.get("visibility", "") == "public"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Public Repo Created",
                    expect_match=True,
                    data=sample_logs.public_repository_created_public_repo_created
                ),
                detection.JSONUnitTest(
                    name="Private Repo Created",
                    expect_match=False,
                    data=sample_logs.public_repository_created_private_repo_created
                ),
                
            ]
        )
    )