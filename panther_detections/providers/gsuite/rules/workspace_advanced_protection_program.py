from panther_sdk import PantherEvent, detection, schema

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_advanced_protection_program"]


def workspace_advanced_protection_program(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Your organization's Google Workspace Advanced Protection Program settings were modified."""

    # todo: convert to match_filters
    def _check_create_setting_evt(event: PantherEvent) -> bool:
        setting_name = event.deep_get("parameters", "SETTING_NAME", default="NO_SETTING_NAME").split("-")[0].strip()
        setting_alert_flag = "Advanced Protection Program Settings"
        return event.get("name") == "CREATE_APPLICATION_SETTING" and setting_name == setting_alert_flag

    def _title(event: PantherEvent) -> str:
        # If no 'dedup' function is defined, the return value of this
        # method will act as deduplication string.
        setting = event.get("parameters", {}).get("SETTING_NAME", "NO_SETTING_NAME")
        setting_name = setting.split("-")[-1].strip()
        return (
            f"Google Workspace Advanced Protection Program settings have been updated to "
            f"[{setting_name}] by Google Workspace User "
            f"[{event.get('actor',{}).get('email','<NO_EMAIL_FOUND>')}]."
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="Google Workspace Advanced Protection Program",
        rule_id="Google.Workspace.Advanced.Protection.Program",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="Your organization's Google Workspace Advanced Protection Program settings were modified.",
        tags=rule_tags(),
        # reports=,
        # reference=,
        runbook="Confirm the changes made were authorized for your organization.",
        alert_title=_title,
        # summary_attrs=,
        threshold=1,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[detection.PythonFilter(func=_check_create_setting_evt)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="parameters json key set to null value",
                    expect_match=False,
                    data=sample_logs.workspace_advanced_protection_program_parameters_json_key_set_to_null_value,
                ),
                detection.JSONUnitTest(
                    name="Allow Security Codes",
                    expect_match=True,
                    data=sample_logs.workspace_advanced_protection_program_allow_security_codes,
                ),
                detection.JSONUnitTest(
                    name="Enable User Enrollment",
                    expect_match=True,
                    data=sample_logs.workspace_advanced_protection_program_enable_user_enrollment,
                ),
                detection.JSONUnitTest(
                    name="New Custom Role Created",
                    expect_match=False,
                    data=sample_logs.workspace_advanced_protection_program_new_custom_role_created,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_advanced_protection_program_listobject_type,
                ),
            ]
        ),
    )
