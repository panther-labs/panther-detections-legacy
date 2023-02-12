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
    "repo_initial_access"
]


def repo_initial_access(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a user initially accesses a private organization repository."""
        #from panther_oss_helpers import get_string_set, put_string_set
    #CODE_ACCESS_ACTIONS = [
    #    "git.clone",
    #    "git.push",
    #    "git.fetch",
    #]

    # def _title(event: PantherEvent) -> str:
    #    return (
    #        f"A user [{event.udm('actor_user')}] accessed a private repository "
    #        f"[{event.get('repo', '<UNKNOWN_REPO>')}] for the first time."
    #    )

    
    
    
    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub User Initial Access to Private Repo",
        rule_id="GitHub.Repo.InitialAccess",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityInfo,
        description="Detects when a user initially accesses a private organization repository.",
        tags=['GitHub'],
        #reports=,
        #reference=,
        #runbook=,
        alert_title=_title,
        #summary_attrs=,
        #threshold=,
        #alert_context=,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    # if the actor field is empty, short circuit the rule
    #    if not event.udm("actor_user"):
    #        return False
    #    if event.get("action") in CODE_ACCESS_ACTIONS and not event.get("repository_public"):
    #        # Compute unique entry for this user + repo
    #        key = get_key(event)
    #        previous_access = get_string_set(key)
    #        if not previous_access:
    #            put_string_set(key, key)
    #            return True
    #    return False

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Initial Access",
                    expect_match=True,
                    data=sample_logs.repo_initial_access_github___initial_access
                ),
                detection.JSONUnitTest(
                    name="GitHub - Repeated Access",
                    expect_match=False,
                    data=sample_logs.repo_initial_access_github___repeated_access
                ),
                detection.JSONUnitTest(
                    name="GitHub - Initial Access Public Repo",
                    expect_match=False,
                    data=sample_logs.repo_initial_access_github___initial_access_public_repo
                ),
                detection.JSONUnitTest(
                    name="GitHub - Clone without Actor",
                    expect_match=False,
                    data=sample_logs.repo_initial_access_github___clone_without_actor
                ),
                
            ]
        )
    )