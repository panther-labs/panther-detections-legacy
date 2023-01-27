from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags

import json
from json import JSONDecodeError

# __all__ = [
#     "rule_tags",
#     "SYSTEM_LOG_TYPE",
#     "SUPPORT_ACCESS_EVENTS",
#     "SUPPORT_RESET_EVENTS",
#     "SHARED_TAGS",
#     "SHARED_SUMMARY_ATTRS",
#     "create_alert_context",
# ]

# SYSTEM_LOG_TYPE = "Okta.SystemLog"


# SHARED_TAGS = [
#     "Okta",
#     standard_tags.IDENTITY_AND_ACCESS_MGMT,
# ]

# SHARED_SUMMARY_ATTRS = [
#     "eventType",
#     "severity",
#     "displayMessage",
#     "p_any_ip_addresses",
# ]

ENDPOINT_REASONS = [
    "endpoint_is_not_in_management_system",
    "endpoint_failed_google_verification",
    "endpoint_is_not_trusted",
    "could_not_determine_if_endpoint_was_trusted",
    "invalid_device",
]

def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]

def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for Duo alerts"""
    return {
        "action": event.get("action", "<action_not_found>"),
        "description": event.get("description", "<description_not_found>"),
        "username": event.get("username", "<username_not_found>"),
        "timestamp": event.get("timestamp", "<timestamp_not_found>"),
    }


def create_alert_context_ip(event: PantherEvent) -> Dict[str, Any]:
    return {
        "factor": event.get("factor"),
        "reason": event.get("reason"),
        "user": event.deep_get("user.name", default=""),
        "os": event.deep_get("access_device.os", default=""),
        "ip_access": event.deep_get("access_device.ip", default=""),
        "ip_auth": event.deep_get("auth_device.ip", default=""),
        "application": event.deep_get("application.name", default=""),
    }


def deserialize_administrator_log_event_description(event: dict) -> dict:
    """Intelligently try and decode a field that is usually stringified json into a python dict.
    This description field seems to take the form of stringified json, So this function
    makes an educated guess on how to transform it into a useful dict structure. and is resilient
    if it's not formed that way
    """
    desc_string = event.get("description", "")
    if desc_string.startswith("{"):
        try:
            # This should be the happy path if the duo docs are correct
            return json.loads(desc_string)
        except JSONDecodeError:
            pass
    elif desc_string.startswith("["):
        try:
            return {"items": json.loads(desc_string)}
        except JSONDecodeError:
            pass

    return {"value": desc_string}

