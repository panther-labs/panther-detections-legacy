from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs

__all__ = ["workspace_apps_marketplace_new_domain_application"]


def workspace_apps_marketplace_new_domain_application(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google Workspace User configured a new domain application from the Google Workspace Apps Marketplace."""

    def _title(event: PantherEvent) -> str:
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method
        # will act as deduplication string.
        return (
            f"Google Workspace User [{event.get('actor',{}).get('email','<NO_EMAIL_PROVIDED>')}] "
            f"enabled a new Google Workspace Marketplace application "
            f"[{event.get('parameters',{}).get('APPLICATION_NAME','<NO_APPLICATION_NAME_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="Google Workspace Apps Marketplace New Domain Application",
        rule_id="Google.Workspace.Apps.Marketplace.New.Domain.Application",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A Google Workspace User configured a new domain application"
        "from the Google Workspace Apps Marketplace.",
        # tags=,
        # reports=,
        # reference=,
        runbook="Confirm this was the intended behavior.",
        alert_title=_title,
        # summary_attrs=,
        threshold=1,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("name", "ADD_APPLICATION"),
            match_filters.deep_equal("parameters.APPLICATION_ENABLED", "true"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Change Email Setting Default",
                    expect_match=False,
                    data=sample_logs.workspace_apps_marketplace_new_domain_application_change_email_setting_default,
                ),
                detection.JSONUnitTest(
                    name="DocuSign for Google",
                    expect_match=True,
                    data=sample_logs.workspace_apps_marketplace_new_domain_application_docusign_for_google,
                ),
                detection.JSONUnitTest(
                    name="Microsoft Apps for Google",
                    expect_match=True,
                    data=sample_logs.workspace_apps_marketplace_new_domain_application_microsoft_apps_for_google,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_apps_marketplace_new_domain_application_listobject_type,
                ),
            ]
        ),
    )
