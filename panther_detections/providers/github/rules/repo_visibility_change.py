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
    "repo_visibility_change"
]


def repo_visibility_change(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when an organization repository visibility changes."""
    
    # def _title(event: PantherEvent) -> str:
    #    repo_access_link = f"https://github.com/{event.get('repo','<UNKNOWN_REPO>')}/settings/access"
    #    return (
    #        f"Repository [{event.get('repo', '<UNKNOWN_REPO>')}] visibility changed. "
    #        f"View current visibility here: {repo_access_link}"
    #    )

    
    
    
    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub Repository Visibility Change",
        rule_id="Github.Repo.VisibilityChange",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityHigh,
        description="Detects when an organization repository visibility changes.",
        tags=['GitHub', 'Exfiltration:Exfiltration Over Web Service'],
        reports={'MITRE ATT&CK': ['TA0010:T1567']},
        #reference=,
        #runbook=,
        alert_title=_title,
        #summary_attrs=,
        #threshold=,
        #alert_context=,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    return event.get("action") == "repo.access"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Repo Visibility Change",
                    expect_match=True,
                    data=sample_logs.repo_visibility_change_github___repo_visibility_change
                ),
                detection.JSONUnitTest(
                    name="GitHub - Repo disabled",
                    expect_match=False,
                    data=sample_logs.repo_visibility_change_github___repo_disabled
                ),
                
            ]
        )
    )