from panther_sdk import schema

from panther_detections.utils import event_type_helpers as event_type

audit_log_type_map = {
    "CREATE_USER": event_type.USER_ACCOUNT_CREATED,
    "DELETE_USER": event_type.USER_ACCOUNT_DELETED,
    "UPDATE_USER": event_type.USER_ACCOUNT_MODIFIED,
    "CREATE_USER_ROLE": event_type.USER_GROUP_CREATED,
    "DELETE_USER_ROLE": event_type.USER_GROUP_DELETED,
    "UPDATE_USER_ROLE": event_type.USER_ROLE_MODIFIED,
}


def get_event_type(event):
    audit_log_type = event.get("actionName")
    matched = audit_log_type_map.get(audit_log_type)
    if matched is not None:
        return matched
    return None


def panther_audit() -> schema.DataModel:
    return schema.DataModel(
        data_model_id="standard.panther.audit",
        name="Panther Audit Model",
        enabled=True,
        log_type=schema.LogTypePantherAudit,
        mappings=[
            schema.DataModelMapping(
                name="source_ip",
                path="sourceIP",
            ),
            schema.DataModelMapping(
                name="user_agent",
                path="userAgent",
            ),
            schema.DataModelMapping(
                name="actor_user",
                path="actionParams.input.email",
            ),
            schema.DataModelMapping(
                name="event_type",
                func=get_event_type,
            ),
        ],
    )
