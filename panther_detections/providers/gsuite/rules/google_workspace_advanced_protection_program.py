import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def google_workspace_advanced_protection_program(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Your organization's Google Workspace Advanced Protection Program settings were modified."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Google Workspace Advanced Protection Program",
        rule_id="Google.Workspace.Advanced.Protection.Program",
        log_types=[SYSTEM_LOG_TYPE],
        tags=(overrides.tags),
        reports="",
        severity=detection.SeverityMedium,
        description="Your organization's Google Workspace Advanced Protection Program settings were modified.",
        reference="",
        runbook="Confirm the changes made were authorized for your organization.",
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
                    name="Allow Security Codes",
                    expect_match=True,
                    data=sample_logs.allow_security_codes
                ),
                detection.JSONUnitTest(
                    name="Enable User Enrollment",
                    expect_match=True,
                    data=sample_logs.enable_user_enrollment
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