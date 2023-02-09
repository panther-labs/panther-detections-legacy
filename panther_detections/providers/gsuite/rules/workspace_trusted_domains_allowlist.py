import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_trusted_domains_allowlist"]


def workspace_trusted_domains_allowlist(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Modified The Trusted Domains List"""

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Workspace Trusted Domains Modified "
            f"[{event.get('name', '<NO_EVENT_NAME>')}] "
            f"with [{event.deep_get('parameters', 'DOMAIN_NAME', default='<NO_DOMAIN_NAME>')}] "
            f"performed by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Workspace Trusted Domain Allowlist Modified",
        rule_id="GSuite.Workspace.TrustedDomainsAllowlist",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Modified The Trusted Domains List",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings#ADD_TRUSTED_DOMAINS",
        runbook="Verify the intent of this modification."
        "If intent cannot be verified, then an indicator search on the actor is advised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("type", "DOMAIN_SETTINGS"),
            match_filters.deep_ends_with("name", "_TRUSTED_DOMAINS"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Remove Trusted Domain",
                    expect_match=True,
                    data=sample_logs.workspace_admin_remove_trusted_domain,
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Add Trusted Domain",
                    expect_match=True,
                    data=sample_logs.workspace_admin_add_trusted_domain,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type,
                ),
            ]
        ),
    )
