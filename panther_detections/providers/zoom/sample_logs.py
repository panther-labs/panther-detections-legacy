import json

admin_to_admin = json.dumps(
    {
        "action": "Batch Update",
        "category_type": "User",
        "operation_detail": "Change Role  - homer.simpson@duff.io: from Admin to Co-Owner",
        "operator": "admin@duff.io",
        "time": "2022-07-05 20:28:48",
    }
)
non_admin_user_update = json.dumps(
    {
        "operator": "homer@panther.io",
        "category_type": "User",
        "action": "Update",
        "operation_detail": "Update User lisa@panther.io  - Job Title: set to Contractor",
    }
)
admin_promotion_event = json.dumps(
    {
        "action": "Batch Update",
        "category_type": "User",
        "operation_detail": "Change Role  - homer.simpson@duff.io: from User to Co-Owner",
        "operator": "admin@duff.io",
        "time": "2022-07-05 20:28:48",
    }
)
member_to_billing_admin_event = json.dumps(
    {
        "action": "Batch Update",
        "category_type": "User",
        "operation_detail": "Change Role  - homer.simpson@duff.io: from Member to Billing Admin",
        "operator": "admin@duff.io",
        "time": "2022-07-05 20:28:48",
    }
)
other_event = json.dumps(
    {
        "action": "SCIM API - Update",
        "category_type": "User",
        "operation_detail": "Edit User homer.simpson@duff.co  - Change Type: from Basic to Licensed",
        "operator": "admin@duff.co",
        "time": "2022-07-01 22:05:22",
    }
)
meeting_passcode_enabled = json.dumps(
    {
        "time": "2021-11-17 00:37:24Z",
        "operator": "homer@panther.io",
        "category_type": "User Group",
        "action": "Update",
        "operation_detail": "Edit Group Springfield  - Personal Meeting ID (PMI) Passcode: from Off to On",
        "p_log_type": "Zoom.Operation",
    }
)
admin_to_billing_admin = json.dumps(
    {
        "action": "Batch Update",
        "category_type": "User",
        "operation_detail": "Change Role  - homer.simpson@duff.io: from Admin to Billing Admin",
        "operator": "admin@duff.io",
        "time": "2022-07-05 20:28:48",
    }
)
admin_to_user = json.dumps(
    {
        "action": "Batch Update",
        "category_type": "User",
        "operation_detail": "Change Role  - homer.simpson@duff.io: from Co-Owner to User",
        "operator": "admin@duff.io",
        "time": "2022-07-05 20:28:48",
    }
)
meeting_passcode_disabled = json.dumps(
    {
        "time": "2021-11-17 00:37:24Z",
        "operator": "homer@panther.io",
        "category_type": "User Group",
        "action": "Update",
        "operation_detail": "Edit Group Springfield  - Personal Meeting ID (PMI) Passcode: from On to Off",
        "p_log_type": "Zoom.Operation",
    }
)
user_granted_admin = json.dumps(
    {
        "operator": "homer@panther.io",
        "category_type": "User",
        "action": "Update",
        "operation_detail": "Update User bart@panther.io  - User Role: from Member to Admin",
    }
)
coowner_to_admin = json.dumps(
    {
        "action": "Batch Update",
        "category_type": "User",
        "operation_detail": "Change Role  - homer.simpson@duff.io: from Co-Owner to Admin",
        "operator": "admin@duff.io",
        "time": "2022-07-05 20:28:48",
    }
)
