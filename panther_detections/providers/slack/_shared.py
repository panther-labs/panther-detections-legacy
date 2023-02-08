from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags

# __all__ = [

# ]

USER_PRIV_ESC_ACTIONS = {
    "owner_transferred": "Slack Owner Transferred",
    "permissions_assigned": "Slack User Assigned Permissions",
    "role_change_to_admin": "Slack User Made Admin",
    "role_change_to_owner": "Slack User Made Owner",
}

LEGAL_HOLD_POLICY_ACTIONS = {
    "legal_hold_policy_entities_deleted": "Slack Legal Hold Policy Entities Deleted",
    "legal_hold_policy_exclusion_added": "Slack Exclusions Added to Legal Hold Policy",
    "legal_hold_policy_released": "Slack Legal Hold Released",
    "legal_hold_policy_updated": "Slack Legal Hold Updated",
}

INFORMATION_BARRIER_ACTIONS = {
    "barrier_deleted": "Slack Information Barrier Deleted",
    "barrier_updated": "Slack Information Barrier Updated",
}

DLP_ACTIONS = [
    "native_dlp_rule_deactivated",
    "native_dlp_violation_deleted",
]

DENIAL_OF_SERVICE_ACTIONS = [
    "bulk_session_reset_by_admin",
    "user_session_invalidated",
    "user_session_reset_by_admin",
]

SHARED_TAGS = [
    "Slack",
]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


def slack_alert_context(event: PantherEvent) -> Dict[str, Any]:
    return {
        "actor-name": event.deep_get("actor", "user", "name", default="<MISSING_NAME>"),
        "actor-email": event.deep_get("actor", "user", "email", default="<MISSING_EMAIL>"),
        "actor-ip": event.deep_get("context", "ip_address", default="<MISSING_IP>"),
        "user-agent": event.deep_get("context", "ua", default="<MISSING_UA>"),
    }


def gen_key(event: PantherEvent) -> str:
    return f"Slack.AuditLogs.ApplicationDoS{event.deep_get('entity', 'user', 'name')}"


def store_reset_info(key, event) -> None:
    from datetime import datetime, timedelta
    from json import dumps

    # Map the user to the most recent reset
    put_string_set(
        key,
        [
            dumps(
                {
                    "time": event.get("p_event_time"),
                }
            )
        ],
    )
    # Expire the entry after 24 hours
    set_key_expiration(key, str((datetime.now() + timedelta(days=1)).timestamp()))
