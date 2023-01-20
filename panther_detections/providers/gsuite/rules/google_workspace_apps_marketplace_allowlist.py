import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def google_workspace_apps_marketplace_allowlist(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Google Workspace Marketplace application allowlist settings were modified."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Google Workspace Apps Marketplace Allowlist",
        rule_id="Google.Workspace.Apps.Marketplace.Allowlist",
        log_types=[SYSTEM_LOG_TYPE],
        tags=(overrides.tags),
        reports="",
        severity=detection.SeverityMedium,
        description="Google Workspace Marketplace application allowlist settings were modified.",
        reference="",
        runbook="Confirm with the acting user that this change was authorized.",
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
                    name="parameters json key set to null value",
                    expect_match=False,
                    data=sample_logs.parameters_json_key_set_to_null_value
                ),
                detection.JSONUnitTest(
                    name="Change Email Setting",
                    expect_match=True,
                    data=sample_logs.change_email_setting
                ),
                detection.JSONUnitTest(
                    name="Change Email Setting Default",
                    expect_match=True,
                    data=sample_logs.change_email_setting_default
                ),
                detection.JSONUnitTest(
                    name="New Custom Role Created",
                    expect_match=False,
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