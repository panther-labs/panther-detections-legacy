from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_password_enforce_strong_disabled"]


def workspace_password_enforce_strong_disabled(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled The Enforcement Of Strong Passwords"""

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Workspace Strong Password Enforcement Has Been Disabled "
            f"By [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite Workspace Strong Password Enforcement Has Been Disabled",
        rule_id="GSuite.Workspace.PasswordEnforceStrongDisabled",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Disabled The Enforcement Of Strong Passwords",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0006:T1110"]},
        reference="https://support.google.com/a/answer/139399?hl=en",
        runbook="Verify the intent of this Password Strength Setting Change."
        "If intent cannot be verified, then a search on the actor's other activities is advised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "admin"),
            match_filters.deep_equal("name", "CHANGE_APPLICATION_SETTING"),
            match_filters.deep_equal("type", "APPLICATION_SETTINGS"),
            match_filters.deep_equal("parameters.NEW_VALUE", "off"),
            match_filters.deep_equal(
                "parameters.SETTING_NAME",
                "Password Management - Enforce strong password",
            ),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Disabled Strong Password Enforcement",
                    expect_match=True,
                    data=sample_logs.workspace_admin_disabled_strong_password_enforcement,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type,
                ),
            ]
        ),
    )
