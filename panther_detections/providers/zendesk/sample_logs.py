import json

zendesk___admin_role_assigned = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "user",
        "source_label": "Bob Cat",
        "action": "update",
        "change_description": "Role changed from End User to Administrator",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___role_changed = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "user",
        "source_label": "Bob Cat",
        "action": "update",
        "change_description": "Role changed from Administrator to End User",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___suspension_disabled = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "user_setting",
        "source_label": "Suspension state: Bob Cat",
        "action": "update",
        "change_description": "Unsuspended",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___suspension_enabled = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "user_setting",
        "source_label": "Suspension state: Bob Cat",
        "action": "create",
        "change_description": "Suspended",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___admin_role_assigned = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "user",
        "source_label": "Account: Account",
        "action": "update",
        "change_description": "Role changed from End User to Administrator",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___mobile_app_access_off = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account_setting",
        "source_label": "Zendesk Support Mobile App Access",
        "action": "create",
        "change_description": "Disabled",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
user_assumption_settings_changed = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account_setting",
        "source_label": "Account Assumption",
        "action": "update",
        "change_description": "Changed",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___api_token_created = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Created",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "api_token",
        "source_label": "API token",
        "action": "create",
        "change_description": "",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___api_token_updated = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "api_token",
        "source_label": "API token: a new description",
        "action": "update",
        "change_description": "description changed from not set to a new description",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___mobile_app_access_on = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account_setting",
        "source_label": "Zendesk Support Mobile App Access",
        "action": "create",
        "change_description": "Enabled",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___credit_card_redaction_off = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account_setting",
        "source_label": "Credit Card Redaction",
        "action": "create",
        "change_description": "Disabled",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___owner_changed = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account",
        "source_label": "Account: Account",
        "action": "update",
        "change_description": "Owner changed from Bob Cat to Mountain Lion",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___credit_card_redaction_on = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account_setting",
        "source_label": "Credit Card Redaction",
        "action": "create",
        "change_description": "Enabled",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
zendesk___credit_card_redaction = json.dumps(
    {
        "url": "https://myzendek.zendesk.com/api/v2/audit_logs/111222333444.json",
        "id": 123456789123,
        "action_label": "Updated",
        "actor_id": 123,
        "source_id": 123,
        "source_type": "account_setting",
        "source_label": "Credit Card Redaction",
        "action": "create",
        "change_description": "Enabled",
        "ip_address": "127.0.0.1",
        "created_at": "2021-05-28T18:39:50Z",
        "p_log_type": "Zendesk.Audit",
    }
)
