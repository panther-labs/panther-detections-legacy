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
    "repo_hook_modified"
]


def repo_hook_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects when a web hook is added, modified, or deleted in an org repository."""
    
    # def _title(event: PantherEvent) -> str:
    #    action = "modified"
    #    if event.get("action").endswith("destroy"):
    #        action = "deleted"
    #    elif event.get("action").endswith("create"):
    #        action = "created"
    #    return f"web hook {action} in repository [{event.get('repo','<UNKNOWN_REPO>')}]"

    # def _severity(event: PantherEvent) -> str:
    #    if event.get("action").endswith("create"):
    #        return "MEDIUM"
    #    return "INFO"

    
    
    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub Web Hook Modified",
        rule_id="GitHub.Repo.HookModified",
        log_types=[schema.GitHubAudit],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityInfo),
        description="Detects when a web hook is added, modified, or deleted in an org repository.",
        tags=['GitHub', 'Exfiltration:Automated Exfiltration'],
        reports={'MITRE ATT&CK': ['TA0010:T1020']},
        #reference=,
        #runbook=,
        alert_title=_title,
        #summary_attrs=,
        #threshold=,
        #alert_context=,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    return event.get("action").startswith("hook.")

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Webhook Created",
                    expect_match=True,
                    data=sample_logs.repo_hook_modified_github___webhook_created
                ),
                detection.JSONUnitTest(
                    name="GitHub - Webhook Deleted",
                    expect_match=True,
                    data=sample_logs.repo_hook_modified_github___webhook_deleted
                ),
                detection.JSONUnitTest(
                    name="GitHub - Non Webhook Event",
                    expect_match=False,
                    data=sample_logs.repo_hook_modified_github___non_webhook_event
                ),
                
            ]
        )
    )