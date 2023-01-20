import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def google_workspace_apps_marketplace_new_domain_application(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google Workspace User configured a new domain application from the Google Workspace Apps Marketplace."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Google Workspace Apps Marketplace New Domain Application",
        rule_id="Google.Workspace.Apps.Marketplace.New.Domain.Application",
        log_types=[SYSTEM_LOG_TYPE],
        tags=(overrides.tags),
        reports="",
        severity=detection.SeverityMedium,
        description="A Google Workspace User configured a new domain application from the Google Workspace Apps Marketplace.",
        reference="",
        runbook="Confirm this was the intended behavior.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=(overrides.summary_attrs),
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Change Email Setting Default",
                    expect_match=False,
                    data=sample_logs.change_email_setting_default
                ),
                detection.JSONUnitTest(
                    name="DocuSign for Google",
                    expect_match=True,
                    data=sample_logs.docusign_for_google
                ),
                detection.JSONUnitTest(
                    name="Microsoft Apps for Google",
                    expect_match=True,
                    data=sample_logs.microsoft_apps_for_google
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )