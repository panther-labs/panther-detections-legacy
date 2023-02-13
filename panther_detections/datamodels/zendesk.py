from panther_sdk import PantherEvent, schema

from panther_detections.providers.zendesk._shared import (
    ZENDESK_CHANGE_DESCRIPTION,
    zendesk_get_roles,
)
from panther_detections.utils import standard_types

# def tracefunc(frame, event, arg, indent=[0]):
#       if event == "call":
#           indent[0] += 2
#           print("-" * indent[0] + "> call function", frame.f_code.co_name)
#       elif event == "return":
#           print("<" + "-" * indent[0], "exit function", frame.f_code.co_name)
#           indent[0] -= 2
#       return tracefunc

# import sys
# sys.setprofile(tracefunc)


ZENDESK_TWO_FACTOR_SOURCES = {
    "Two-Factor authentication for all admins and agents",
    "Require Two Factor",
}


def get_user_event_type(event: PantherEvent) -> str:
    # check for login events

    if event.get("action") == "login":
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower().startswith("successful sign-in"):
            return standard_types.SUCCESSFUL_LOGIN
    # check for admin assignment
    if event.get("action") == "update":
        _, new_role = zendesk_get_roles(event)  # pylint: disable=W0632
        if new_role and is_admin_role(new_role):
            return standard_types.ADMIN_ROLE_ASSIGNED
    return None


def get_event_type(event: PantherEvent) -> str:
    # user related events
    from panther_detections.datamodels.zendesk import get_user_event_type

    if event.get("source_type", "") == "user":
        return get_user_event_type(event)
    # account related events
    if event.get("source_type", "") == "account_setting":
        return get_account_setting_event_type(event)
    return None


def get_account_setting_event_type(event: PantherEvent) -> str:
    if event.get("source_label", "") in ZENDESK_TWO_FACTOR_SOURCES:
        if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "disabled":
            return standard_types.MFA_DISABLED
    return None


def is_admin_role(new_role) -> bool:
    if new_role and isinstance(new_role, str):
        for admin in ("admin", "account owner"):
            if admin in new_role.lower():
                return True
    return False


def get_assigned_admin_role(event: PantherEvent) -> str:
    _, new_role = zendesk_get_roles(event)  # pylint: disable=W0632
    if is_admin_role(new_role):
        return new_role
    return None


def get_user(event: PantherEvent) -> str:
    # some events will have the user in the source_label field,
    # otherwise the user field may not be relevant
    if event.get("source_type", "").lower() == "user":
        return event.get("source_label")
    return "<UNKNOWN_USER>"


def zendesk() -> schema.DataModel:
    return schema.DataModel(
        data_model_id="zendesk.audit.model",
        name="Zendesk Audit Model",
        log_type=schema.LogTypeZendeskAudit,
        mappings=[
            schema.DataModelMapping(
                name="actor_user",
                path="$.actor_id",
            ),
            schema.DataModelMapping(
                name="source_ip",
                path="$.ip_address",
            ),
            schema.DataModelMapping(
                name="assigned_admin_role",
                func=get_assigned_admin_role,
            ),
            schema.DataModelMapping(
                name="event_type",
                func=get_event_type,
            ),
            schema.DataModelMapping(
                name="user",
                func=get_user,
            ),
        ],
    )
