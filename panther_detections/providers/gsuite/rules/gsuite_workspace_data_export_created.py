import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_data_export_created(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Created a Data Export"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Data Export Has Been Created",
        rule_id="GSuite.Workspace.DataExportCreated",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Created a Data Export",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/data-studio#DATA_EXPORT",
        runbook="Verify the intent of this Data Export. If intent cannot be verified, then a search on the actor's other activities is advised.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['actor:email']
        ,
        threshold="",
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Data Export Created",
                    expect_match=True,
                    data=sample_logs.workspace_admin_data_export_created
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Data Export Succeeded",
                    expect_match=True,
                    data=sample_logs.workspace_admin_data_export_succeeded
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )