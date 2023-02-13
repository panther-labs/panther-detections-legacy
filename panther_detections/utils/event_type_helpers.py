# a place to hold event type constants used among many data models, rules, or policies

__all__ = [
    "ADMIN_ROLE_ASSIGNED",
    "FAILED_LOGIN",
    "MFA_DISABLED",
    "MFA_ENABLED",
    "MFA_RESET",
    "SUCCESSFUL_LOGIN",
    "SUCCESSFUL_LOGOUT",
    "USER_ACCOUNT_CREATED",
    "ACCOUNT_CREATED",
    "USER_ACCOUNT_DELETED",
    "USER_ACCOUNT_MODIFIED",
    "USER_GROUP_CREATED",
    "USER_GROUP_MODIFIED",
    "USER_GROUP_DELETED",
    "USER_ROLE_CREATED",
    "USER_ROLE_MODIFIED",
    "USER_ROLE_DELETE",
    "ADMIN_MFA_DISABLED",
]

ADMIN_ROLE_ASSIGNED = "admin_role_assigned"
FAILED_LOGIN = "failed_login"
MFA_DISABLED = "mfa_disabled"
MFA_ENABLED = "mfa_enabled"
MFA_RESET = "mfa_reset"
SUCCESSFUL_LOGIN = "successful_login"
SUCCESSFUL_LOGOUT = "successful_logout"
USER_ACCOUNT_CREATED = "user_account_created"
# ACCOUNT_CREATED refers to an account not associated with a specific user,
# such as a billing account
ACCOUNT_CREATED = "account_created"
# USER_ACCOUNT_CREATED refers to an account that is associated with one user or service user
USER_ACCOUNT_DELETED = "user_account_deleted"
USER_ACCOUNT_MODIFIED = "user_account_modified"
USER_GROUP_CREATED = "user_group_created"
USER_GROUP_MODIFIED = "user_group_modified"
USER_GROUP_DELETED = "user_group_deleted"
USER_ROLE_CREATED = "user_role_created"
USER_ROLE_MODIFIED = "user_role_modified"
USER_ROLE_DELETED = "user_role_deleted"
# ADMIN_MFA_DISABLED refers to MFA being disabled for an entire org, account, or similar
ADMIN_MFA_DISABLED = "admin_mfa_disabled"
