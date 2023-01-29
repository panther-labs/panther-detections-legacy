from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags
import re

# key names
ZENDESK_CHANGE_DESCRIPTION = "change_description"
ZENDESK_APP_ROLE_ASSIGNED = re.compile(
    r"(?P<app>.*) role changed from (?P<old_role>.+) to (?P<new_role>.*)", re.IGNORECASE
)
ZENDESK_ROLE_ASSIGNED = re.compile(
    r"Role changed from (?P<old_role>.+) to (?P<new_role>[^$]+)", re.IGNORECASE
)


def zendesk_get_roles(event):
    old_role = ""
    new_role = ""
    role_change = event.get(ZENDESK_CHANGE_DESCRIPTION, "")
    if "\n" in role_change:
        for app_change in role_change.split("\n"):
            matches = ZENDESK_APP_ROLE_ASSIGNED.match(app_change)
            if matches:
                if old_role:
                    old_role += " ; "
                old_role += matches.group("app") + ":" + matches.group("old_role")
                if new_role:
                    new_role += " ; "
                new_role += matches.group("app") + ":" + matches.group("new_role")
    else:
        matches = ZENDESK_ROLE_ASSIGNED.match(role_change)
        if matches:
            old_role = matches.group("old_role")
            new_role = matches.group("new_role")
    if not old_role:
        old_role = "<UNKNOWN_APP>:<UNKNOWN_ROLE>"
    if not new_role:
        new_role = "<UNKNOWN_APP>:<UNKNOWN_ROLE>"
    return old_role, 

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

# SUPPORT_ACCESS_EVENTS = [
#     "user.session.impersonation.grant",
#     "user.session.impersonation.initiate",
# ]

# SUPPORT_RESET_EVENTS = [
#     "user.account.reset_password",
#     "user.mfa.factor.update",
#     "system.mfa.factor.deactivate",
#     "user.mfa.attempt_bypass",
# ]

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


# def rule_tags(*extra_tags: str) -> List[str]:
#     return [*SHARED_TAGS, *extra_tags]


# def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
#     """Returns common context for Okta alerts"""

#     return {
#         "ips": event.get("p_any_ip_addresses", []),
#         "actor": event.get("actor", ""),
#         "target": event.get("target", ""),
#         "client": event.get("client", ""),
#     }
