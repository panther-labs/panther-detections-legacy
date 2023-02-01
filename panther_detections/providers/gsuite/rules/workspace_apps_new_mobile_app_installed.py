import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["workspace_apps_new_mobile_app_installed"]


def workspace_apps_new_mobile_app_installed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps."""

    def _title(event: PantherEvent) -> str:
        # If no 'dedup' function is defined, the return value of
        # this method will act as deduplication string.
        mobile_app_pkg_id = event.get("parameters", {}).get("MOBILE_APP_PACKAGE_ID", "<NO_MOBILE_APP_PACKAGE_ID_FOUND>")
        return (
            f"Google Workspace User [{event.get('actor',{}).get('email','<NO_EMAIL_FOUND>')}] "
            f"added application "
            f"[{mobile_app_pkg_id}] "
            f"to your org's mobile application allowlist for "
            f"[{event.get('parameters',{}).get('DEVICE_TYPE','<NO_DEVICE_TYPE_FOUND>')}]."
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Google Workspace Apps New Mobile App Installed",
        rule_id="Google.Workspace.Apps.New.Mobile.App.Installed",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityMedium,
        description="A new mobile application was added to your organization's mobile apps whitelist in Google Workspace Apps.",
        # tags=,
        # reports=,
        # reference=,
        runbook="https://admin.google.com/ac/apps/unified",
        alert_title=_title,
        # summary_attrs=,
        threshold=1,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("name", "ADD_MOBILE_APPLICATION_TO_WHITELIST")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Android Calculator",
                    expect_match=True,
                    data=sample_logs.workspace_apps_new_mobile_app_installed_android_calculator,
                ),
                detection.JSONUnitTest(
                    name="Enable User Enrollement",
                    expect_match=False,
                    data=sample_logs.workspace_apps_new_mobile_app_installed_enable_user_enrollement,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_apps_new_mobile_app_installed_listobject_type,
                ),
            ]
        ),
    )
