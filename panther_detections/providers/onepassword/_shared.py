from typing import Any, Dict, List

from panther_sdk import PantherEvent

__all__ = [
    "rule_tags",
    "SYSTEM_LOG_TYPE",
    "SHARED_TAGS",
    "SHARED_SUMMARY_ATTRS",
    "create_unusual_client_alert_context",
    "create_sensitive_item_access_alert_context",
]

SYSTEM_LOG_TYPE = "OnePassword.SignInAttempt"


SHARED_TAGS = ["1Password"]

SHARED_SUMMARY_ATTRS = ["p_any_ip_addresses", "p_any_emails"]


CLIENT_ALLOWLIST = [
    "1Password CLI",
    "1Password for Web",
    "1Password for Mac",
    "1Password SCIM Bridge",  # Used for automated account provisioning
    "1Password for Windows",
    "1Password for iOS",
    "1Password Browser Extension",
    "1Password for Android",
]

SENSITIVE_ITEM_WATCHLIST = {"ecd1d435c26440dc930ddfbbef201a11": "demo_item"}


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


def create_unusual_client_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns 1Password Unusual Client Context"""

    context = {}
    context["user"] = event.deep_get("target_user", "name", default="UNKNOWN_USER")
    context["user_email"] = event.udm("actor_user")
    context["ip_address"] = event.udm("source_ip")
    context["client"] = event.deep_get("client", "app_name", default="UNKNOWN_CLIENT")
    context["OS"] = event.deep_get("client", "os_name", default="UNKNOWN_OS")
    context["login_result"] = event.get("category")
    context["time_seen"] = event.get("timestamp")

    return context


def create_sensitive_item_access_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns 1Password Sensitive Item Access Context"""

    context = {
        "user": event.deep_get("user", "name"),
        "item_name": event.deep_get("p_enrichment", "1Password Translation", "item_uuid", "title"),
        "client": event.deep_get("client", "app_name"),
        "ip_address": event.udm("source_ip"),
        "event_time": event.get("timestamp"),
    }

    return context
