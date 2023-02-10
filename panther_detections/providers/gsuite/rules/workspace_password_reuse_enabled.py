from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_password_reuse_enabled"]


def workspace_password_reuse_enabled(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Enabled Password Reuse"""

    def _new_value_true(event: PantherEvent):
        return event.deep_get("parameters", "NEW_VALUE").lower()

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Workspace Password Reuse Has Been Enabled "
            f"By [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite Workspace Password Reuse Has Been Enabled",
        rule_id="GSuite.Workspace.PasswordReuseEnabled",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Enabled Password Reuse",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0006:T1110"]},
        reference="https://support.google.com/a/answer/139399?hl=en#",
        runbook="Verify the intent of this Password Reuse Setting Change. If intent cannot be verified, then a search"
        "on the actor's other activities is advised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("id.applicationName", "admin"),
            match_filters.deep_equal("type", "APPLICATION_SETTINGS"),
            detection.PythonFilter(func=_new_value_true),
            match_filters.deep_equal("parameters.SETTING_NAME", "Password Management - Enable password reuse"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Enabled Password Reuse",
                    expect_match=True,
                    data=sample_logs.workspace_admin_enabled_password_reuse,
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
