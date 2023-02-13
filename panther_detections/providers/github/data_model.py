from panther_sdk import PantherEvent, schema

from panther_detections.utils import event_type_helpers


def get_admin_role(_) -> str:
    # github doesn't record the admin role in the event
    return "<UNKNOWN_ROLE>"


def get_event_type(event: PantherEvent) -> str:
    if event.get("action") == "team.promote_maintainer":
        return event_type_helpers.ADMIN_ROLE_ASSIGNED
    if event.get("action") == "org.disable_two_factor_requirement":
        return event_type_helpers.MFA_DISABLED
    return None


def github_audit() -> schema.DataModel:
    return schema.DataModel(
        data_model_id="standard.github.audit",
        name="GitHub Audit Model",
        enabled=True,
        log_type=schema.LogTypeGitHubAudit,
        mappings=[
            schema.DataModelMapping(
                name="actor_user",
                path="actor",
            ),
            schema.DataModelMapping(
                name="assigned_admin_role",
                func=get_admin_role,
            ),
            schema.DataModelMapping(
                name="event_type",
                func=get_event_type,
            ),
            schema.DataModelMapping(
                name="user",
                path="user",
            ),
        ],
    )
