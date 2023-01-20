import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def google_workspace_apps_new_mobile_app_installed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Google Workspace Apps New Mobile App Installed",
        rule_id="Google.Workspace.Apps.New.Mobile.App.Installed",
        log_types=[SYSTEM_LOG_TYPE],
        tags=(overrides.tags),
        reports="",
        severity=detection.SeverityMedium,
        description="A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps.",
        reference="",
        runbook="https://admin.google.com/ac/apps/unified",
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
                    name="Android Calculator",
                    expect_match=True,
                    data=sample_logs.android_calculator
                ),
                detection.JSONUnitTest(
                    name="Enable User Enrollement",
                    expect_match=False,
                    data=sample_logs.enable_user_enrollement
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )