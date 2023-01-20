import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def google_workspace_admin_custom_role(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google Workspace administrator created a new custom administrator role."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Google Workspace Admin Custom Role",
        rule_id="Google.Workspace.Admin.Custom.Role",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['admin', 'administrator', 'google workspace', 'role'],
        ),
        reports="",
        severity=detection.SeverityMedium,
        description="A Google Workspace administrator created a new custom administrator role.",
        reference="",
        runbook="Please review this activity with the administrator and ensure this behavior was authorized.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['actor.email', 'name', 'type']
        ,
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Delete Role",
                    expect_match=False,
                    data=sample_logs.delete_role
                ),
                detection.JSONUnitTest(
                    name="New Custom Role Created",
                    expect_match=True,
                    data=sample_logs.new_custom_role_created
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )