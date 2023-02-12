import typing
from panther_sdk import PantherEvent, detection, schema
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = [
    "org_ip_allowlist"
]


def org_ip_allowlist(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Detects changes to a GitHub Org IP Allow List"""
        #ALLOWLIST_ACTIONS = [
    #    "ip_allow_list.enable",
    #    "ip_allow_list.disable",
    #    "ip_allow_list.enable_for_installed_apps",
    #    "ip_allow_list.disable_for_installed_apps",
    #    "ip_allow_list_entry.create",
    #    "ip_allow_list_entry.update",
    #    "ip_allow_list_entry.destroy",
    #]

    # def _title(event: PantherEvent) -> str:
    #    return f"GitHub Org IP Allow list modified by {event.get('actor')}."

    
    
    
    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        #enabled=,
        name="GitHub Org IP Allow List modified",
        rule_id="GitHub.Org.IpAllowlist",
        log_types=[schema.GitHubAudit],
        severity=detection.SeverityMedium,
        description="Detects changes to a GitHub Org IP Allow List",
        tags=['GitHub', 'Persistence:Account Manipulation'],
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        #reference=,
        runbook="Verify that the change was authorized and appropriate.",
        alert_title=_title,
        summary_attrs=['actor', 'action'],
        #threshold=,
        #alert_context=,
        #alert_grouping=,
        filters=[
            # def rule(event):
    #    return (
    #        event.get("action").startswith("ip_allow_list") and event.get("action") in ALLOWLIST_ACTIONS
    #    )

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="GitHub - IP Allow list modified",
                    expect_match=True,
                    data=sample_logs.org_ip_allowlist_github___ip_allow_list_modified
                ),
                detection.JSONUnitTest(
                    name="GitHub - IP Allow list disabled",
                    expect_match=True,
                    data=sample_logs.org_ip_allowlist_github___ip_allow_list_disabled
                ),
                detection.JSONUnitTest(
                    name="GitHub - Non IP Allow list action",
                    expect_match=False,
                    data=sample_logs.org_ip_allowlist_github___non_ip_allow_list_action
                ),
                
            ]
        )
    )