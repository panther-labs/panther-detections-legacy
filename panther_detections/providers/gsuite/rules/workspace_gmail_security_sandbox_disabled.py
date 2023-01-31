import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def workspace_gmail_security_sandbox_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled The Security Sandbox"""

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get
            if not deep_get(event, "id", "applicationName", default="").lower() == "admin":
                return False
            if all(
                [
                    (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
                    (deep_get(event, "parameters", "APPLICATION_NAME",
                              default="").lower() == "gmail"),
                    (deep_get(event, "parameters", "NEW_VALUE",
                              default="").lower() == "false"),
                    (
                        deep_get(event, "parameters",
                                 "SETTING_NAME", default="")
                        == "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
                    ),
                ]
            ):
                return True
            return False
        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Gmail Security Sandbox was disabled "
            f"for [{event.deep_get('parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] "
            f"by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Workspace Gmail Security Sandbox Disabled",
        rule_id="GSuite.Workspace.GmailSecuritySandboxDisabled",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Disabled The Security Sandbox",
        tags=['GSuite'],
        reports={'MITRE ATT&CK': ['TA0001:T1566']},
        reference="https://support.google.com/a/answer/7676854?hl=en#zippy=%2Cfind-security-sandbox-settings%2Cabout-security-sandbox-rules-and-other-scans",
        runbook="Gmail's Security Sandbox enables rule based scanning of email content. If this change was not intentional, inspect the other actions taken by this actor.",
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
                    name="Workspace Admin Disables Security Sandbox",
                    expect_match=True,
                    data=sample_logs.workspace_gmail_security_sandbox_disabled_workspace_admin_disables_security_sandbox
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=False,
                    data=sample_logs.workspace_gmail_security_sandbox_disabled_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_gmail_security_sandbox_disabled_listobject_type
                ),

            ]
        )
    )
