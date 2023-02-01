import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["workspace_trusted_domains_allowlist"]


def workspace_trusted_domains_allowlist(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Modified The Trusted Domains List"""

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            return event.get("type") == "DOMAIN_SETTINGS" and event.get("name", "").endswith("_TRUSTED_DOMAINS")

        return detection.PythonFilter(func=_rule_filter)

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
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Modified The Trusted Domains List",
        tags=["GSuite"],
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-domain-settings#ADD_TRUSTED_DOMAINS",
        runbook="Verify the intent of this modification. If intent cannot be verified, then an indicator search on the actor is advised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or []) + [rule_filter()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Remove Trusted Domain",
                    expect_match=True,
                    data=sample_logs.workspace_trusted_domains_allowlist_workspace_admin_remove_trusted_domain,
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Add Trusted Domain",
                    expect_match=True,
                    data=sample_logs.workspace_trusted_domains_allowlist_workspace_admin_add_trusted_domain,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=False,
                    data=sample_logs.workspace_trusted_domains_allowlist_admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_trusted_domains_allowlist_listobject_type,
                ),
            ]
        ),
    )
