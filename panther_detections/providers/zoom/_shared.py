from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags


def get_zoom_user_context(event: PantherEvent):
    """
    Parses the operation_detail field of Zoom.Operation events related to Users
    to provide usable fields for use in detections
    """
    operation_context = {}
    raw_string = event.get("operation_detail", "")
    category_type = event.get("category_type")
    action = event.get("action")

    if category_type == "User":
        if action in ("Add", "Delete"):
            operation_context["User"] = raw_string.split()[2].strip()
            operation_context["Department"] = raw_string.split("-")[2].split(":")[1].strip()
            operation_context["UserType"] = raw_string.split("-")[1].split(":")[1].strip()

        if action == "Update":
            operation_context["User"] = raw_string.split()[2]
            operation_context["Change"] = " ".join((raw_string.split("-"))).strip()
            operation_context["DisabledSetting"] = "On to Off" in operation_context["Change"]
            operation_context["EnabledSetting"] = "Off to On" in operation_context["Change"]

    return operation_context


def get_zoom_usergroup_context(event: PantherEvent):
    """
    Parses the operation_detail field of Zoom.Operation events related to User Groups
    to provide usable fields for use in detections
    """
    operation_context = {}
    raw_string = event.get("operation_detail", "")
    category_type = event.get("category_type")
    action = event.get("action")

    if category_type == "User Group":
        if action == "Add":
            operation_context["GroupName"] = " ".join(raw_string.split()[2:])

        if action == "Delete":
            operation_context["GroupName"] = " ".join(raw_string.split()[1:])

        if action == "Update":
            operation_context["GroupName"] = " ".join(raw_string.split("-")[0].split()[2:])
            operation_context["Change"] = raw_string.split("-")[1].strip()
            operation_context["DisabledSetting"] = "On to Off" in operation_context["Change"]
            operation_context["EnabledSetting"] = "Off to On" in operation_context["Change"]

    return operation_context


def get_zoom_room_context(event: PantherEvent):
    """
    Parses the operation_detail field of Zoom.Operation events related to Zoom Meeting Rooms
    to provide usable fields for use in detections
    """
    operation_context = {}
    raw_string = event.get("operation_detail", "")
    category_type = event.get("category_type")
    action = event.get("action")

    if category_type == "Zoom Rooms":
        if action == "Update":
            operation_context["Parameter"] = raw_string.split("-")[0]
            operation_context["CurrentState"] = raw_string.split("-")[1].split(":")[1].strip()
            operation_context["PreviousState"] = raw_string.split("-")[2].split(":")[1].strip()
            operation_context["LockStatus"] = raw_string.split("-")[3].split(":")[1].strip()
            operation_context["Affected"] = raw_string.split("-")[4].split(":")[1].strip()

    return operation_context


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
