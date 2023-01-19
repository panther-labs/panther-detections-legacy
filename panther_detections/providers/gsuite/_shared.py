from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags

__all__ = [
    "rule_tags",
    "ACTIVITY_LOG_TYPE",
    "REPORTS_LOG_TYPE",
    "SHARED_TAGS",
    "SHARED_SUMMARY_ATTRS",
    "create_alert_context",
]

ACTIVITY_LOG_TYPE = "GSuite.ActivityEvent"
REPORTS_LOG_TYPE = "GSuite.Reports"

SHARED_TAGS = [
    "GSuite",
    standard_tags.IDENTITY_AND_ACCESS_MGMT,
]

SHARED_SUMMARY_ATTRS = [
    "eventType",
    "severity",
    "displayMessage",
    "p_any_ip_addresses",
]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for GSuite alerts"""

    return {
        "ips": event.get("p_any_ip_addresses", []),
        "actor": event.get("actor", ""),
        "target": event.get("target", ""),
        "client": event.get("client", ""),
    }

