import re
from typing import List

__all__ = [
    "rule_tags",
    "USER_SUSPENSION_ACTIONS",
    "MOBILE_APP_ACTIONS",
    "API_TOKEN_ACTIONS",
    "SHARED_TAGS",
    "REDACTION_ACTIONS",
    "ZENDESK_CHANGE_DESCRIPTION",
    "ZENDESK_APP_ROLE_ASSIGNED",
    "ZENDESK_ROLE_ASSIGNED",
    "ZENDESK_OWNER_CHANGED",
    "zendesk_get_roles",
]


SHARED_TAGS = [
    "Zendesk",
]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


USER_SUSPENSION_ACTIONS = ["create", "update"]
MOBILE_APP_ACTIONS = ["create", "update"]
API_TOKEN_ACTIONS = ["create", "destroy"]
REDACTION_ACTIONS = ["create", "destroy"]


# key names
ZENDESK_CHANGE_DESCRIPTION = "change_description"
ZENDESK_APP_ROLE_ASSIGNED = re.compile(
    r"(?P<app>.*) role changed from (?P<old_role>.+) to (?P<new_role>.*)", re.IGNORECASE
)
ZENDESK_ROLE_ASSIGNED = re.compile(r"Role changed from (?P<old_role>.+) to (?P<new_role>[^$]+)", re.IGNORECASE)
ZENDESK_OWNER_CHANGED = re.compile(r"Owner changed from (?P<old_owner>.+) to (?P<new_owner>[^$]+)", re.IGNORECASE)


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
    return (old_role, new_role)
