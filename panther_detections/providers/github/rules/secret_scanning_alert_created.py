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
    "secret_scanning_alert_created"
]


def secret_scanning_alert_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """GitHub detected a secret and created a secret scanning alert."""
    
    # def _title(event: PantherEvent) -> str:
    #    return f"Github detected a secret in {event.get('repo')} (#{event.get('number')})"

    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return {
    #        "repo": event.get("repo"),
    #        "alert #": event.get("number"),
    #        "url": f"https://github.com/{event.get('repo')}/security/secret-scanning/"
    #        f"{event.get('number')}",
    #    }

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub Secret Scanning Alert Created",
        rule_id="GitHub.Secret.Scanning.Alert.Created",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityMedium,
        description="GitHub detected a secret and created a secret scanning alert.",
        tags=['GitHub'],
        reports={'MITRE ATT&CK': ['TA0006:T1552']},
        #reference=,
        runbook="Review the secret to determine if it needs to be revoked or the alert suppressed.",
        alert_title=_title,
        #summary_attrs=,
        #threshold=,
        alert_context=_alert_context,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    return event.get("action") == "secret_scanning_alert.create"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub detected a secret",
                    expect_match=True,
                    data=sample_logs.secret_scanning_alert_created_github_detected_a_secret
                ),
                detection.JSONUnitTest(
                    name="Unrelated",
                    expect_match=False,
                    data=sample_logs.secret_scanning_alert_created_unrelated
                ),
                
            ]
        )
    )