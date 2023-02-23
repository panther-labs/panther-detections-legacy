from typing import Any, Dict, List

from panther_sdk import PantherEvent

__all__ = ["rule_tags", "SYSTEM_LOG_TYPE", "SHARED_TAGS", "create_alert_context"]

SYSTEM_LOG_TYPE = "Atlassian.Audit"


SHARED_TAGS = ["Atlassian", "User impersonation"]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for Atlassian alerts"""

    return {
        "Timestamp": event.deep_get("attributes", "time", default="<unknown-time>"),
        "Actor": event.deep_get("attributes", "actor", "email", default="<unknown-actor-email>"),
        "Impersonated user": event.deep_get("attributes", "context", default=[{}])[0]
        .get("attributes", {})
        .get("email", "<unknown-email>"),
        "Event ID": event.get("id"),
    }
