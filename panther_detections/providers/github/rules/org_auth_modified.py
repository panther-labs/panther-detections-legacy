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
    "org_auth_modified"
]


def org_auth_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects changes to GitHub org authentication changes."""
        #AUTH_CHANGE_EVENTS = [
    #    "org.saml_disabled",
    #    "org.saml_enabled",
    #    "org.disable_two_factor_requirement",
    #    "org.enable_two_factor_requirement",
    #    "org.update_saml_provider_settings",
    #    "org.enable_oauth_app_restrictions",
    #    "org.disable_oauth_app_restrictions",
    #]

    # def _title(event: PantherEvent) -> str:
    #    return f"GitHub auth configuration was changed by {event.get('actor', '<UNKNOWN USER>')}"

    
    
    
    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub Org Authentication Method Changed",
        rule_id="GitHub.Org.AuthChange",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityCritical,
        description="Detects changes to GitHub org authentication changes.",
        tags=['GitHub', 'Persistence:Account Manipulation'],
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        #reference=,
        runbook="Verify that the GitHub admin performed this activity and validate its use.",
        alert_title=_title,
        summary_attrs=['actor', 'action'],
        #threshold=,
        #alert_context=,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    if not event.get("action").startswith("org."):
    #        return False
    #    return event.get("action") in AUTH_CHANGE_EVENTS

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - Authentication Method Changed",
                    expect_match=True,
                    data=sample_logs.org_auth_modified_github___authentication_method_changed
                ),
                detection.JSONUnitTest(
                    name="GitHub - Non Auth Related Org Change",
                    expect_match=False,
                    data=sample_logs.org_auth_modified_github___non_auth_related_org_change
                ),
                
            ]
        )
    )