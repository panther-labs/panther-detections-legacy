import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def workspace_password_reuse_enabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Enabled Password Reuse"""

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get
            if not deep_get(event, "id", "applicationName", default="").lower() == "admin":
                return False
            if all(
                [
                    (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
                    (event.get("type", "") == "APPLICATION_SETTINGS"),
                    (deep_get(event, "parameters", "NEW_VALUE",
                     default="").lower() == "true"),
                    (
                        deep_get(event, "parameters",
                                 "SETTING_NAME", default="")
                        == "Password Management - Enable password reuse"
                    ),
                ]
            ):
                return True
            return False
        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Workspace Password Reuse Has Been Enabled "
            f"By [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Workspace Password Reuse Has Been Enabled",
        rule_id="GSuite.Workspace.PasswordReuseEnabled",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Enabled Password Reuse",
        tags=['GSuite'],
        reports={'MITRE ATT&CK': ['TA0006:T1110']},
        reference="https://support.google.com/a/answer/139399?hl=en#",
        runbook="Verify the intent of this Password Reuse Setting Change. If intent cannot be verified, then a search on the actor's other activities is advised.",
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            rule_filter()
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Enabled Password Reuse",
                    expect_match=True,
                    data=sample_logs.workspace_password_reuse_enabled_workspace_admin_enabled_password_reuse
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=False,
                    data=sample_logs.workspace_password_reuse_enabled_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_password_reuse_enabled_listobject_type
                ),

            ]
        )
    )
