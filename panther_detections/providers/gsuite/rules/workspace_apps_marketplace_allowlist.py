from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

__all__ = ["workspace_apps_marketplace_allowlist"]


def workspace_apps_marketplace_allowlist(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Google Workspace Marketplace application allowlist settings were modified."""

    def _title(event: PantherEvent) -> str:
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this
        # method will act as deduplication string.
        value_dict = {
            "DEFAULT": "DEFAULT",
            "1": "Don't allow users to install and run apps from the Marketplace",
            "2": "Allow users to install and run any app from the Marketplace",
            "3": "Allow users to install and run only selected apps from the Marketplace",
        }
        old_val = event.deep_get("parameters", "OLD_VALUE", default="<NO_OLD_VALUE_FOUND>")
        new_val = event.deep_get("parameters", "NEW_VALUE", default="<NO_NEW_VALUE_FOUND>")
        actor = event.deep_get("actor", "email", default="<NO_EMAIL_FOUND>")
        return (
            f"Google Workspace User [{actor}] "
            f"made an application allowlist setting change from [{value_dict.get(old_val)}] "
            f"to [{value_dict.get(new_val)}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="Google Workspace Apps Marketplace Allowlist",
        rule_id="Google.Workspace.Apps.Marketplace.Allowlist",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="Google Workspace Marketplace application allowlist settings were modified.",
        # tags=,
        # reports=,
        # reference=,
        runbook="Confirm with the acting user that this change was authorized.",
        alert_title=_title,
        # summary_attrs=,
        threshold=1,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("parameters.SETTING_NAME", "ENABLE_G_SUITE_MARKETPLACE"),
            match_filters.deep_not_equal("parameters.OLD_VALUE", "parameters.NEW_VALUE"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="parameters json key set to null value",
                    expect_match=False,
                    data=sample_logs.workspace_apps_marketplace_allowlist_parameters_json_key_set_to_null_value,
                ),
                detection.JSONUnitTest(
                    name="Change Email Setting",
                    expect_match=True,
                    data=sample_logs.workspace_apps_marketplace_allowlist_change_email_setting,
                ),
                detection.JSONUnitTest(
                    name="Change Email Setting Default",
                    expect_match=True,
                    data=sample_logs.workspace_apps_marketplace_allowlist_change_email_setting_default,
                ),
                detection.JSONUnitTest(
                    name="New Custom Role Created",
                    expect_match=False,
                    data=sample_logs.workspace_apps_marketplace_allowlist_new_custom_role_created,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_apps_marketplace_allowlist_listobject_type,
                ),
            ]
        ),
    )
