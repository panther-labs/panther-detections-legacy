import json

legal_hold_policy_modified_legal_hold___entities_deleted = json.dumps(
    {
        "action": "legal_hold_policy_entities_deleted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
legal_hold_policy_modified_legal_hold___exclusions_added = json.dumps(
    {
        "action": "legal_hold_policy_exclusion_added",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
legal_hold_policy_modified_legal_hold___policy_released = json.dumps(
    {
        "action": "legal_hold_policy_released",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
legal_hold_policy_modified_legal_hold___policy_updated = json.dumps(
    {
        "action": "legal_hold_policy_updated",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
legal_hold_policy_modified_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
app_access_expanded_app_scopes_expanded = json.dumps(
    {
        "action": "app_scopes_expanded",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 16:48:14",
        "details": {
            "granular_bot_token": true,
            "is_internal_integration": false,
            "is_token_rotation_enabled_app": false,
            "new_scopes": [
                "app_mentions:read",
                "channels:join",
                "channels:read",
                "chat:write",
                "chat:write.public",
                "team:read",
                "users:read",
                "im:history",
                "groups:read",
                "reactions:write",
                "groups:history",
                "channels:history",
            ],
            "previous_scopes": [
                "app_mentions:read",
                "commands",
                "channels:join",
                "channels:read",
                "chat:write",
                "chat:write.public",
                "users:read",
                "groups:read",
                "reactions:write",
                "groups:history",
                "channels:history",
            ],
        },
        "entity": {
            "type": "workspace",
            "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
        },
        "id": "9d9b76ce-47bb-4838-a96a-1b5fd4d1b564",
    }
)
app_access_expanded_app_resources_added = json.dumps(
    {
        "action": "app_resources_added",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "entity": {
            "type": "workspace",
            "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
app_access_expanded_app_resources_granted = json.dumps(
    {
        "action": "app_resources_granted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 16:48:14",
        "details": {
            "export_end_ts": "2022-07-28 09:48:12",
            "export_start_ts": "2022-07-27 09:48:12",
            "export_type": "STANDARD",
        },
        "entity": {
            "type": "workspace",
            "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
        },
        "id": "9d9b76ce-47bb-4838-a96a-1b5fd4d1b564",
    }
)
app_access_expanded_bot_token_upgraded = json.dumps(
    {
        "action": "bot_token_upgraded",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "entity": {
            "type": "workspace",
            "workspace": {"domain": "test-workspace-1", "id": "T01234N56GB", "name": "test-workspace-1"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
app_access_expanded_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
information_barrier_modified_information_barrier_deleted = json.dumps(
    {
        "action": "barrier_deleted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
information_barrier_modified_information_barrier_updated = json.dumps(
    {
        "action": "barrier_updated",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
information_barrier_modified_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
passthrough_anomaly_name = json.dumps(
    {
        "action": "anomaly",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
passthrough_anomaly_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
user_privilege_escalation_owner_transferred = json.dumps(
    {
        "action": "owner_transferred",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
user_privilege_escalation_permissions_assigned = json.dumps(
    {
        "action": "permissions_assigned",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
user_privilege_escalation_role_changed_to_admin = json.dumps(
    {
        "action": "role_change_to_admin",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
user_privilege_escalation_role_changed_to_owner = json.dumps(
    {
        "action": "role_change_to_owner",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
user_privilege_escalation_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
private_channel_made_public_private_channel_made_public = json.dumps(
    {
        "action": "private_channel_converted_to_public",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
private_channel_made_public_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
org_deleted_organization_deleted = json.dumps(
    {
        "action": "organization_deleted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
org_deleted_organization_created = json.dumps(
    {
        "action": "organization_created",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
mfa_settings_changed_mfa_auth_changed = json.dumps(
    {
        "action": "pref.two_factor_auth_changed",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
mfa_settings_changed_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
service_owner_transferred_service_owner_transferred = json.dumps(
    {
        "action": "service_owner_transferred",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
service_owner_transferred_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
potentially_malicious_file_shared_malicious_content_detected = json.dumps(
    {
        "action": "file_malicious_content_detected",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
potentially_malicious_file_shared_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
ekm_config_changed_ekm_config_changed = json.dumps(
    {
        "action": "ekm_logging_config_set",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
ekm_config_changed_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
ekm_slackbot_unenrolled_ekm_slackbot_unenrolled = json.dumps(
    {
        "action": "ekm_slackbot_unenroll_notification_sent",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
ekm_slackbot_unenrolled_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
intune_mdm_disabled_intune_disabled = json.dumps(
    {
        "action": "intune_disabled",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
intune_mdm_disabled_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
ekm_unenrolled_ekm_unenrolled = json.dumps(
    {
        "action": "ekm_unenrolled",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
ekm_unenrolled_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
sso_settings_changed_sso_setting_changed = json.dumps(
    {
        "action": "pref.sso_setting_changed",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
sso_settings_changed_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
idp_configuration_change_idp_configuration_added = json.dumps(
    {
        "action": "idp_configuration_added",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 16:48:14",
    }
)
idp_configuration_change_idp_configuration_deleted = json.dumps(
    {
        "action": "idp_configuration_deleted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 16:48:14",
    }
)
idp_configuration_change_idp_configuration_updated = json.dumps(
    {
        "action": "idp_prod_configuration_updated",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 16:48:14",
    }
)
idp_configuration_change_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
org_created_organization_created = json.dumps(
    {
        "action": "organization_created",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
org_created_organization_deleted = json.dumps(
    {
        "action": "organization_deleted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
app_removed_app_restricted = json.dumps(
    {
        "action": "app_restricted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "E012MH3HS94"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-panther-1",
                "id": "T01770N79GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Go-http-client/2.0",
        },
        "date_create": "2021-06-08 22:16:15",
        "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": true},
        "entity": {
            "app": {
                "id": "A012F34BFEF",
                "is_directory_approved": false,
                "is_distributed": false,
                "name": "app-name",
                "scopes": ["admin"],
            },
            "type": "app",
        },
    }
)
app_removed_app_uninstalled = json.dumps(
    {
        "action": "app_uninstalled",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "E012MH3HS94"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-panther-1",
                "id": "T01770N79GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Go-http-client/2.0",
        },
        "date_create": "2021-06-08 22:16:15",
        "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": true},
        "entity": {
            "app": {
                "id": "A012F34BFEF",
                "is_directory_approved": false,
                "is_distributed": false,
                "name": "app-name",
                "scopes": ["admin"],
            },
            "type": "app",
        },
    }
)
app_removed_app_removed_from_workspace = json.dumps(
    {
        "action": "org_app_workspace_removed",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "E012MH3HS94"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-panther-1",
                "id": "T01770N79GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Go-http-client/2.0",
        },
        "date_create": "2021-06-08 22:16:15",
        "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": true},
        "entity": {
            "app": {
                "id": "A012F34BFEF",
                "is_directory_approved": false,
                "is_distributed": false,
                "name": "app-name",
                "scopes": ["admin"],
            },
            "type": "app",
        },
    }
)
app_removed_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
app_added_app_approved = json.dumps(
    {
        "action": "app_installed",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "E012MH3HS94"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-panther-1",
                "id": "T01770N79GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Go-http-client/2.0",
        },
        "date_create": "2021-06-08 22:16:15",
        "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": true},
        "entity": {
            "app": {
                "id": "A012F34BFEF",
                "is_directory_approved": false,
                "is_distributed": false,
                "name": "app-name",
                "scopes": ["admin"],
            },
            "type": "app",
        },
    }
)
app_added_app_installed = json.dumps(
    {
        "action": "app_installed",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "E012MH3HS94"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-panther-1",
                "id": "T01770N79GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Go-http-client/2.0",
        },
        "date_create": "2021-06-08 22:16:15",
        "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": true},
        "entity": {
            "app": {
                "id": "A012F34BFEF",
                "is_directory_approved": false,
                "is_distributed": false,
                "name": "app-name",
                "scopes": ["admin"],
            },
            "type": "app",
        },
    }
)
app_added_app_added_to_workspace = json.dumps(
    {
        "action": "app_installed",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "E012MH3HS94"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-panther-1",
                "id": "T01770N79GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Go-http-client/2.0",
        },
        "date_create": "2021-06-08 22:16:15",
        "details": {"app_owner_id": "W012J3AEWAU", "is_internal_integration": true},
        "entity": {
            "app": {
                "id": "A012F34BFEF",
                "is_directory_approved": false,
                "is_distributed": false,
                "name": "app-name",
                "scopes": ["admin"],
            },
            "type": "app",
        },
    }
)
app_added_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
dlp_modified_native_dlp_rule_deactivated = json.dumps(
    {
        "action": "native_dlp_rule_deactivated",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
dlp_modified_native_dlp_violation_deleted = json.dumps(
    {
        "action": "native_dlp_violation_deleted",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "A012B3CDEFG", "name": "username", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace",
                "id": "T01234N56GB",
                "name": "test-workspace",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
dlp_modified_user_logout = json.dumps(
    {
        "action": "user_logout",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
        "date_create": "2022-07-28 15:22:32",
        "entity": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "id": "72cac009-9eb3-4dde-bac6-ee49a32a1789",
    }
)
application_dos_user_session_reset___first_time = json.dumps(
    {
        "action": "user_session_reset_by_admin",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
application_dos_user_session_reset___multiple_times = json.dumps(
    {
        "action": "user_session_reset_by_admin",
        "actor": {
            "type": "user",
            "user": {"email": "user@example.com", "id": "W012J3FEWAU", "name": "primary-owner", "team": "T01234N56GB"},
        },
        "context": {
            "ip_address": "1.2.3.4",
            "location": {
                "domain": "test-workspace-1",
                "id": "T01234N56GB",
                "name": "test-workspace-1",
                "type": "workspace",
            },
            "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
        },
    }
)
