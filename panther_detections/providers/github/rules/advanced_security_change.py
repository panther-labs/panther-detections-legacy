from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import ADV_SEC_ACTIONS, github_alert_context, rule_tags

__all__ = ["advanced_security_change"]


def advanced_security_change(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """The rule alerts when GitHub Security tools (Dependabot, Secret Scanner, etc) are disabled."""

    def _title(event: PantherEvent) -> str:
        action = event.get("action", "")
        advanced_sec_text = ""
        # pylint: disable=line-too-long
        # https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security#about-advanced-security-features
        if "advanced_security" in action or "secret_scanning" in action:
            advanced_sec_text = "Advanced "
        return f"Change detected to GitHub {advanced_sec_text}Security - {event.get('action', '')}"

    def _severity(event: PantherEvent) -> str:
        return ADV_SEC_ACTIONS.get(event.get("action", ""), "Low")

    def _group_by(event: PantherEvent) -> str:
        # 1. Actor
        # 2. Action
        # We should dedup on actor - action
        actor = event.get("actor", "<NO_ACTOR>")
        action = event.get("action", "<NO_ACTION>")
        return "_".join([actor, action])

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GitHub Security Change, includes GitHub Advanced Security",
        rule_id="GitHub.Advanced.Security.Change",
        log_types=[schema.LogTypeGitHubAudit],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityLow),
        description="The rule alerts when GitHub Security tools (Dependabot, Secret Scanner, etc) are disabled.",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0005:T1562"]},
        # reference=,
        runbook="Confirm with GitHub administrators and re-enable the tools as applicable.",
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        alert_context=github_alert_context,
        alert_grouping=detection.AlertGrouping(group_by=_group_by, period_minutes=15),
        filters=[match_filters.deep_in("action", ADV_SEC_ACTIONS)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Secret Scanning Disabled on a Repo",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_secret_scanning_disabled_on_a_repo,
                ),
                detection.JSONUnitTest(
                    name="Secret Scanning Disabled Org Wide",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_secret_scanning_disabled_org_wide,
                ),
                detection.JSONUnitTest(
                    name="Secret Scanning Disabled for New Repos",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_secret_scanning_disabled_for_new_repos,
                ),
                detection.JSONUnitTest(
                    name="Dependabot Alerts Disabled Org Wide",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_dependabot_alerts_disabled_org_wide,
                ),
                detection.JSONUnitTest(
                    name="Dependabot Alerts Disabled on New Repos",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_dependabot_alerts_disabled_on_new_repos,
                ),
                detection.JSONUnitTest(
                    name="Dependabot Disabled Org Wide",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_dependabot_disabled_org_wide,
                ),
                detection.JSONUnitTest(
                    name="Dependabot Disabled on New Repos",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_dependabot_disabled_on_new_repos,
                ),
                detection.JSONUnitTest(
                    name="Non-GitHub Adv Sec Action",
                    expect_match=False,
                    data=sample_logs.advanced_security_change_non_github_adv_sec_action,
                ),
                detection.JSONUnitTest(
                    name="Enterprise Log - business_advanced_security.enabled",
                    expect_match=False,
                    data=sample_logs.advanced_security_change_enterprise_log_business_advanced_security_enabled,
                ),
                detection.JSONUnitTest(
                    name="Enterprise Log - business_advanced_security.disabled",
                    expect_match=True,
                    data=sample_logs.advanced_security_change_enterprise_log_business_advanced_security_disabled,
                ),
            ]
        ),
    )
