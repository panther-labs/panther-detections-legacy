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
    "organization_app_integration_installed"
]


def organization_app_integration_installed(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """An application integration was installed to your organization's Github account by someone in your organization."""
        #from panther_base_helpers import github_alert_context

    # def _title(event: PantherEvent) -> str:
    #    # (Optional) Return a string which will be shown as the alert title.
    #    # If no 'dedup' function is defined, the return value of this method
    #    # will act as deduplication string.
    #    return (
    #        f" Github User [{event.get('actor',{})}] in [{event.get('org')}] "
    #        f"installed the following integration: [{event.get('name')}]."
    #    )
    ## 
    
    # def _group_by(event: PantherEvent) -> str:
    ##  (Optional) Return a string which will be used to deduplicate similar alerts.
    ## return ''

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    #  (Optional) Return a dictionary with additional data to be included in the
    #    #  alert sent to the SNS/SQS/Webhook destination
    #    return github_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="Github Organization App Integration Installed",
        rule_id="Github.Organization.App.Integration.Installed",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityLow,
        description="An application integration was installed to your organization's Github account by someone in your organization.",
        tags=['Application Installation', 'Github'],
        #reports=,
        reference="https://docs.github.com/en/enterprise-server@3.4/developers/apps/managing-github-apps/installing-github-apps",
        runbook="Confirm that the app integration installation was a desired behavior.",
        alert_title=_title,
        summary_attrs=['actor', 'name', 'org'],
        threshold=1,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(group_by=_group_by, period_minutes=60),
        filters=[
            # def rule(event):
    #    # Return True to match the log event and trigger an alert.
    #    # Creates a new alert if the event's action was ""
    #    return event.get("action") == "integration_installation.create"

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="App Integration Installation",
                    expect_match=True,
                    data=sample_logs.organization_app_integration_installed_app_integration_installation
                ),
                detection.JSONUnitTest(
                    name="App Integration Installation-2",
                    expect_match=True,
                    data=sample_logs.organization_app_integration_installed_app_integration_installation_2
                ),
                detection.JSONUnitTest(
                    name="Repository Archived",
                    expect_match=False,
                    data=sample_logs.organization_app_integration_installed_repository_archived
                ),
                
            ]
        )
    )