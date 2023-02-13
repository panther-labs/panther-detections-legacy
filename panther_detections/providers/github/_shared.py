from typing import Any, Dict, List

from panther_sdk import PantherEvent

__all__ = [
    "ADV_SEC_ACTIONS",
    "SHARED_TAGS",
    "AUTH_CHANGE_EVENTS",
    "ALLOWLIST_ACTIONS",
    "rule_tags",
    "github_alert_context",
]

# List of actions in markdown format
# pylint: disable=line-too-long
# https://github.com/github/docs/blob/main/content/admin/monitoring-activity-in-your-enterprise/reviewing-audit-logs-for-your-enterprise/audit-log-events-for-your-enterprise.md
# grep '^| `' audit-log-events-for-your-enterprise.md.txt | sed -e 's/\| //' -e 's/`//g' | awk -F\| '{if ($1 ~ /business/) {print $1}}'
# pylint: enable=line-too-long

# {GitHub Action: Alert Severity}
ADV_SEC_ACTIONS = {
    "dependabot_alerts.disable": "CRITICAL",
    "dependabot_alerts_new_repos.disable": "HIGH",
    "dependabot_security_updates.disable": "CRITICAL",
    "dependabot_security_updates_new_repos.disable": "HIGH",
    "repository_secret_scanning_push_protection.disable": "HIGH",
    "secret_scanning.disable": "CRITICAL",
    "secret_scanning_new_repos.disable": "HIGH",
    "bypass": "MEDIUM",  # Bypass secret scanner push protection for a detected secret.
    # pylint: disable=line-too-long
    # The events that begin with "business" are seemingly from enterprise logs
    # business.disable_oidc  -  OIDC single sign-on was disabled for an enterprise.
    "business.disable_oidc": "CRITICAL",
    # business.disable_saml  -  SAML single sign-on was disabled for an enterprise.
    "business.disable_saml": "CRITICAL",
    # business.disable_two_factor_requirement  -  The requirement for members to
    #    have two-factor authentication enabled to access an enterprise was disabled.
    "business.disable_two_factor_requirement": "CRITICAL",
    # business.members_can_update_protected_branches.disable  -  The ability for
    #    enterprise members to update branch protection rules was disabled.
    #    Only enterprise owners can update protected branches.
    "business.members_can_update_protected_branches.disable": "MEDIUM",
    # business.referrer_override_disable  -  An enterprise owner or site administrator
    #    disabled the referrer policy override.
    "business.referrer_override_disable": "MEDIUM",
    # business_advanced_security.disabled  -  {% data
    #    variables.product.prodname_GH_advanced_security %}
    #    was disabled for your enterprise. For more information, see "[Managing
    #    {% data variables.product.prodname_GH_advanced_security %}
    #    features for your enterprise]
    #    (/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_advanced_security.disabled": "CRITICAL",
    # business_advanced_security.disabled_for_new_repos  -  {% data
    #    variables.product.prodname_GH_advanced_security %} was disabled for
    #    new repositories in your enterprise. For more information, see
    #    "[Managing {% data variables.product.prodname_GH_advanced_security %} features
    #    for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_advanced_security.disabled_for_new_repos": "HIGH",
    # business_secret_scanning.disable  -  {% data variables.product.prodname_secret_scanning_caps %} was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning.disable": "CRITICAL",
    # business_secret_scanning.disabled_for_new_repos  -  {% data variables.product.prodname_secret_scanning_caps %} was disabled for new repositories in your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning.disabled_for_new_repos": "CRITICAL",
    # business_secret_scanning_custom_pattern_push_protection.disabled  -  Push protection for a custom pattern for {% data variables.product.prodname_secret_scanning %} was disabled for your enterprise. For more information, see "[Defining custom patterns for {% data variables.product.prodname_secret_scanning %}](/code-security/secret-scanning/defining-custom-patterns-for-secret-scanning#defining-a-custom-pattern-for-an-enterprise-account)."
    "business_secret_scanning_custom_pattern_push_protection.disabled": "HIGH",
    # business_secret_scanning_push_protection.disable  -  Push protection for {% data variables.product.prodname_secret_scanning %} was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning_push_protection.disable": "CRITICAL",
    # business_secret_scanning_push_protection.disabled_for_new_repos  -  Push protection for {% data variables.product.prodname_secret_scanning %} was disabled for new repositories in your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning_push_protection.disabled_for_new_repos": "HIGH",
    # business_secret_scanning_push_protection_custom_message.disable  -  The custom message triggered by an attempted push to a push-protected repository was disabled for your enterprise. For more information, see "[Managing {% data variables.product.prodname_GH_advanced_security %} features for your enterprise](/admin/code-security/managing-github-advanced-security-for-your-enterprise/managing-github-advanced-security-features-for-your-enterprise)."
    "business_secret_scanning_push_protection_custom_message.disable": "XXXX",
    #
    # There are also correlating github _org_ level events
    "org.advanced_security_disabled_for_new_repos": "HIGH",
    "org.advanced_security_disabled_on_all_repos": "CRITICAL",
    # org.advanced_security_policy_selected_member_disabled - An enterprise owner prevented {% data variables.product.prodname_GH_advanced_security %} features from being enabled for repositories owned by the organization. {% data reusables.advanced-security.more-information-about-enforcement-policy %}
    # pylint: enable=line-too-long
    "org.advanced_security_policy_selected_member_disabled": "HIGH",
    "repo.advanced_security_disabled": "CRITICAL",
    "repo.advanced_security_policy_selected_member_disabled": "HIGH",
}

SHARED_TAGS = ["GitHub"]

AUTH_CHANGE_EVENTS = [
    "org.saml_disabled",
    "org.saml_enabled",
    "org.disable_two_factor_requirement",
    "org.enable_two_factor_requirement",
    "org.update_saml_provider_settings",
    "org.enable_oauth_app_restrictions",
    "org.disable_oauth_app_restrictions",
]

ALLOWLIST_ACTIONS = [
    "ip_allow_list.enable",
    "ip_allow_list.disable",
    "ip_allow_list.enable_for_installed_apps",
    "ip_allow_list.disable_for_installed_apps",
    "ip_allow_list_entry.create",
    "ip_allow_list_entry.update",
    "ip_allow_list_entry.destroy",
]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


def github_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for GitHub detections"""

    return {
        "action": event.get("action", ""),
        "actor": event.get("actor", ""),
        "actor_location": event.deep_get("actor_location", "country_code"),
        "org": event.get("org", ""),
        "repo": event.get("repo", ""),
        "user": event.get("user", ""),
    }
