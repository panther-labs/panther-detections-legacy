import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_gmail_security_sandbox_disabled"]


def workspace_gmail_security_sandbox_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled The Security Sandbox"""

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
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Disabled The Security Sandbox",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0001:T1566"]},
        # pylint: disable=line-too-long
        reference="https://support.google.com/a/answer/7676854?hl=en#zippy=%2Cfind-security-sandbox-settings%2Cabout-security-sandbox-rules-and-other-scans",
        runbook="Gmail's Security Sandbox enables rule based scanning of email content."
        "If this change was not intentional, inspect the other actions taken by this actor.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "admin"),
            match_filters.deep_equal("name", "CHANGE_APPLICATION_SETTING"),
            match_filters.deep_in("parameters.APPLICATION_NAME", {"gmail", "Gmail"}),
            match_filters.deep_in("parameters.NEW_VALUE", {"false", "False"}),
            match_filters.deep_equal(
                "parameters.SETTING_NAME",
                "AttachmentDeepScanningSettingsProto deep_scanning_enabled",
            ),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Disables Security Sandbox",
                    expect_match=True,
                    data=sample_logs.workspace_admin_disables_security_sandbox,
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
