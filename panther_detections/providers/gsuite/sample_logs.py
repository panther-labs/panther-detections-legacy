import json

workspace_apps_marketplace_allowlist_parameters_json_key_set_to_null_value = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "111111111111111111111"
    },
    "id": {
        "applicationName": "user_accounts",
        "customerId": "C00000000",
        "time": "2022-12-29 22:42:44.467000000",
        "uniqueQualifier": "517500000000000000"
    },
    "parameters": None,
    "ipAddress": "2600:2600:2600:2600:2600:2600:2600:2600",
    "kind": "admin#reports#activity",
    "name": "recovery_email_edit",
    "type": "recovery_info_change"
})

workspace_advanced_protection_program_parameters_json_key_set_to_null_value = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "111111111111111111111"
    },
    "id": {
        "applicationName": "user_accounts",
        "customerId": "C00000000",
        "time": "2022-12-29 22:42:44.467000000",
        "uniqueQualifier": "517500000000000000"
    },
    "parameters": None,
    "ipAddress": "2600:2600:2600:2600:2600:2600:2600:2600",
    "kind": "admin#reports#activity",
    "name": "recovery_email_edit",
    "type": "recovery_info_change"
})

drive_external_share_dangerous_share_of_known_document_with_a_missing_user = json.dumps({
    "kind": "admin#reports#activity",
    "id": {
        "time": "2020-09-07T15:50:49.617Z",
        "uniqueQualifier": "1111111111111111111",
        "applicationName": "drive",
        "customerId": "C010qxghg"
    },
    "actor": {
        "email": "example@acme.com",
        "profileId": "1111111111111111111"
    },
    "events": [
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "outside@acme.com"
                },
                {
                    "name": "old_visibility",
                    "value": "private"
                },
                {
                    "name": "doc_id",
                    "value": "1111111111111111111"
                },
                {
                    "name": "doc_type",
                    "value": "document"
                },
                {
                    "name": "doc_title",
                    "value": "Document Title Primary"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                },
                {
                    "name": "originating_app_id",
                    "value": "1111111111111111111"
                },
                {
                    "name": "owner_is_shared_drive",
                    "boolValue": False
                },
                {
                    "name": "owner_is_team_drive",
                    "boolValue": False
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_edit"
                    ]
                }
            ]
        }
    ]
})
drive_external_share_dangerous_share_of_unknown_document = json.dumps({
    "kind": "admin#reports#activity",
    "id": {
        "time": "2020-09-07T15:50:49.617Z",
        "uniqueQualifier": "1111111111111111111",
        "applicationName": "drive",
        "customerId": "C010qxghg"
    },
    "actor": {
        "email": "example@acme.com",
        "profileId": "1111111111111111111"
    },
    "events": [
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "alice@external.com"
                },
                {
                    "name": "old_visibility",
                    "value": "private"
                },
                {
                    "name": "doc_id",
                    "value": "1111111111111111111"
                },
                {
                    "name": "doc_type",
                    "value": "document"
                },
                {
                    "name": "doc_title",
                    "value": "Untitled document"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                },
                {
                    "name": "originating_app_id",
                    "value": "1111111111111111111"
                },
                {
                    "name": "owner_is_shared_drive",
                    "boolValue": False
                },
                {
                    "name": "owner_is_team_drive",
                    "boolValue": False
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_edit"
                    ]
                }
            ]
        }
    ]
})
drive_external_share_share_allowed_by_exception = json.dumps({
    "kind": "admin#reports#activity",
    "id": {
        "time": "2020-07-07T15:50:49.617Z",
        "uniqueQualifier": "1111111111111111111",
        "applicationName": "drive",
        "customerId": "C010qxghg"
    },
    "actor": {
        "email": "alice@acme.com",
        "profileId": "1111111111111111111"
    },
    "events": [
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "billable",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_domain",
                    "value": "acme.com"
                },
                {
                    "name": "old_visibility",
                    "value": "private"
                },
                {
                    "name": "doc_id",
                    "value": "1111111111111111111"
                },
                {
                    "name": "doc_type",
                    "value": "document"
                },
                {
                    "name": "doc_title",
                    "value": "Document Title Pattern"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                },
                {
                    "name": "originating_app_id",
                    "value": "1111111111111111111"
                },
                {
                    "name": "owner_is_shared_drive",
                    "boolValue": False
                },
                {
                    "name": "owner_is_team_drive",
                    "boolValue": False
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "people_within_domain_with_link"
                    ]
                }
            ]
        }
    ]
})
drive_overly_visible_access_event = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "type": "access",
            "name": "download"
        }
    ]
})
drive_overly_visible_modify_event_without_over_visibility = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "type": "access",
            "name": "edit",
            "parameters": [
                {
                    "name": "visibility",
                    "value": "private"
                }
            ]
        }
    ]
})
drive_overly_visible_overly_visible_doc_modified = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "type": "access",
            "name": "edit",
            "parameters": [
                {
                    "name": "visibility",
                    "value": "people_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "my shared document"
                }
            ]
        }
    ]
})
drive_visibility_change_access_event = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "type": "access",
            "name": "upload"
        }
    ]
})
drive_visibility_change_acl_change_without_visibility_change = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "type": "acl_change",
            "name": "shared_drive_settings_change"
        }
    ]
})
drive_visibility_change_doc_became_public_link_unrestricted = json.dumps({
    "actor": {
        "email": "bobert@gmail.com"
    },
    "events": [
        {
            "parameters": [
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "doc_title",
                    "value": "my shared document"
                },
                {
                    "name": "target_domain",
                    "value": "all"
                },
                {
                    "name": "visibility",
                    "value": "people_with_link"
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "people_with_link"
                    ]
                }
            ],
            "name": "change_document_visibility",
            "type": "acl_change"
        },
        {
            "parameters": [
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                }
            ],
            "name": "change_document_access_scope",
            "type": "acl_change"
        }
    ],
    "id": {
        "applicationName": "drive"
    },
    "p_row_id": "111222"
})
drive_visibility_change_doc_became_public_link_allowlisted_domain_not_configured = json.dumps({
    "actor": {
        "email": "bobert@example.com"
    },
    "events": [
        {
            "parameters": [
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "doc_title",
                    "value": "my shared document"
                },
                {
                    "name": "target_domain",
                    "value": "example.com"
                },
                {
                    "name": "visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "people_with_link"
                    ]
                }
            ],
            "name": "change_document_visibility",
            "type": "acl_change"
        },
        {
            "parameters": [
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                }
            ],
            "name": "change_document_access_scope",
            "type": "acl_change"
        }
    ],
    "id": {
        "applicationName": "drive"
    },
    "p_row_id": "111222"
})
drive_visibility_change_doc_became_public_link_allowlisted_domain_is_configured = json.dumps({
    "actor": {
        "email": "bobert@example.com"
    },
    "events": [
        {
            "parameters": [
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "doc_title",
                    "value": "my shared document"
                },
                {
                    "name": "target_domain",
                    "value": "example.com"
                },
                {
                    "name": "visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "people_with_link"
                    ]
                }
            ],
            "name": "change_document_visibility",
            "type": "acl_change"
        },
        {
            "parameters": [
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                }
            ],
            "name": "change_document_access_scope",
            "type": "acl_change"
        }
    ],
    "id": {
        "applicationName": "drive"
    },
    "p_row_id": "111222"
})
drive_visibility_change_doc_became_private___link = json.dumps({
    "actor": {
        "email": "bobert@example.com"
    },
    "events": [
        {
            "parameters": [
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "doc_title",
                    "value": "my shared document"
                },
                {
                    "name": "target_domain",
                    "value": "all"
                },
                {
                    "name": "visibility",
                    "value": "people_with_link"
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "private"
                    ]
                }
            ],
            "name": "change_document_visibility",
            "type": "acl_change"
        }
    ],
    "id": {
        "applicationName": "drive"
    },
    "p_row_id": "111222"
})
drive_visibility_change_doc_became_public___user = json.dumps({
    "id": {
        "applicationName": "drive"
    },
    "actor": {
        "email": "bobert@example.com"
    },
    "kind": "admin#reports#activity",
    "ipAddress": "1.1.1.1",
    "events": [
        {
            "type": "access",
            "name": "edit",
            "parameters": [
                {
                    "name": "primary_event"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "someone@random.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        }
    ]
})
drive_visibility_change_doc_became_public_user_multiple = json.dumps({
    "id": {
        "applicationName": "drive"
    },
    "actor": {
        "email": "bobert@example.com"
    },
    "kind": "admin#reports#activity",
    "ipAddress": "1.1.1.1",
    "events": [
        {
            "type": "access",
            "name": "edit",
            "parameters": [
                {
                    "name": "primary_event"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "someone@random.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "someoneelse@random.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "notbobert@example.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        }
    ]
})
drive_visibility_change_doc_inherits_folder_permissions = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "name": "change_user_access_hierarchy_reconciled",
            "type": "acl_change",
            "parameters": [
                {
                    "name": "visibility_change",
                    "value": "internal"
                }
            ]
        }
    ]
})
drive_visibility_change_doc_inherits_folder_permissions___sharing_link = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "name": "change_document_access_scope_hierarchy_reconciled",
            "type": "acl_change",
            "parameters": [
                {
                    "name": "visibility_change",
                    "value": "internal"
                }
            ]
        }
    ]
})
drive_visibility_change_doc_became_public___public_email_provider = json.dumps({
    "id": {
        "applicationName": "drive"
    },
    "actor": {
        "email": "bobert@example.com"
    },
    "kind": "admin#reports#activity",
    "ipAddress": "1.1.1.1",
    "events": [
        {
            "type": "access",
            "name": "edit",
            "parameters": [
                {
                    "name": "primary_event"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "someone@yandex.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        }
    ]
})
drive_visibility_change_doc_shared_with_multiple_users_all_from_allowed_domains = json.dumps({
    "id": {
        "applicationName": "drive"
    },
    "actor": {
        "email": "bobert@example.com"
    },
    "kind": "admin#reports#activity",
    "ipAddress": "1.1.1.1",
    "events": [
        {
            "type": "access",
            "name": "edit",
            "parameters": [
                {
                    "name": "primary_event"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "someone@notexample.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "someoneelse@example.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        },
        {
            "type": "acl_change",
            "name": "change_user_access",
            "parameters": [
                {
                    "name": "primary_event",
                    "boolValue": True
                },
                {
                    "name": "visibility_change",
                    "value": "external"
                },
                {
                    "name": "target_user",
                    "value": "notbobert@example.com"
                },
                {
                    "name": "old_value",
                    "multiValue": [
                        "none"
                    ]
                },
                {
                    "name": "new_value",
                    "multiValue": [
                        "can_view"
                    ]
                },
                {
                    "name": "old_visibility",
                    "value": "people_within_domain_with_link"
                },
                {
                    "name": "doc_title",
                    "value": "Hosted Accounts"
                },
                {
                    "name": "visibility",
                    "value": "shared_externally"
                }
            ]
        }
    ]
})
drive_visibility_change_deprecated_any_event = json.dumps({
    "p_row_id": "111222",
    "actor": {
        "email": "bobert@example.com"
    },
    "id": {
        "applicationName": "drive"
    },
    "events": [
        {
            "type": "access",
            "name": "upload"
        }
    ]
})

suspicious_logins_normal_login_event = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "kind": "admin#reports#activity",
    "type": "account_warning",
    "name": "login_success",
    "parameters": {
        "affected_email_address": "bobert@ext.runpanther.io"
    }
})
suspicious_logins_account_warning_not_for_suspicious_login = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "kind": "admin#reports#activity",
    "type": "account_warning",
    "name": "account_disabled_spamming",
    "parameters": {
        "affected_email_address": "bobert@ext.runpanther.io"
    }
})
suspicious_logins_account_warning_for_suspicious_login = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "kind": "admin#reports#activity",
    "type": "account_warning",
    "name": "suspicious_login",
    "parameters": {
        "affected_email_address": "bobert@ext.runpanther.io"
    }
})
mobile_device_screen_unlock_fail_normal_mobile_event = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "DEVICE_SYNC_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io"
    }
})
mobile_device_screen_unlock_fail_small_number_of_failed_logins = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io",
        "FAILED_PASSWD_ATTEMPTS": 2
    }
})
mobile_device_screen_unlock_fail_multiple_failed_login_attempts_with_int_type = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io",
        "FAILED_PASSWD_ATTEMPTS": 100
    }
})
mobile_device_screen_unlock_fail_multiple_failed_login_attempts_with_string_type = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io",
        "FAILED_PASSWD_ATTEMPTS": "100"
    }
})
workspace_gmail_default_routing_rule_workspace_admin_creates_default_routing_rule = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "110555555555555555555"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 00:50:03.493000000",
        "uniqueQualifier": "-6333333333333333333"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_GMAIL_SETTING",
    "parameters": {
        "SETTING_NAME": "MESSAGE_SECURITY_RULE",
        "USER_DEFINED_SETTING_NAME": "44444"
    },
    "type": "EMAIL_SETTINGS"
})
workspace_gmail_default_routing_rule_workspace_admin_deletes_default_routing_rule = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "110555555555555555555"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 00:50:41.760000000",
        "uniqueQualifier": "-5015136739334825037"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "DELETE_GMAIL_SETTING",
    "parameters": {
        "SETTING_NAME": "MESSAGE_SECURITY_RULE",
        "USER_DEFINED_SETTING_NAME": "44444"
    },
    "type": "EMAIL_SETTINGS"
})
workspace_gmail_default_routing_rule_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_ONLY_ACCESS",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_gmail_default_routing_rule_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
workspace_apps_new_mobile_app_installed_android_calculator = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-10 22:55:38.478000000",
        "uniqueQualifier": "12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "ADD_MOBILE_APPLICATION_TO_WHITELIST",
    "parameters": {
        "DEVICE_TYPE": "Android",
        "DISTRIBUTION_ENTITY_NAME": "/",
        "DISTRIBUTION_ENTITY_TYPE": "ORG_UNIT",
        "MOBILE_APP_PACKAGE_ID": "com.google.android.calculator"
    },
    "type": "MOBILE_SETTINGS"
})
workspace_apps_new_mobile_app_installed_enable_user_enrollement = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:35:29.906000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "standard",
        "APPLICATION_NAME": "Security",
        "NEW_VALUE": "True",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "Advanced Protection Program Settings - Enable user enrollment"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_apps_new_mobile_app_installed_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
gov_attack_normal_login_event = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "homer.simpson@example.com"
    },
    "type": "login",
    "name": "login_success",
    "parameters": {
        "is_suspicious": None,
        "login_challenge_method": [
            "none"
        ]
    }
})
gov_attack_government_backed_attack_warning = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "homer.simpson@example.com"
    },
    "type": "login",
    "name": "gov_attack_warning",
    "parameters": {
        "is_suspicious": None,
        "login_challenge_method": [
            "none"
        ]
    }
})
workspace_admin_custom_role_delete_role = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "123456"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 02:57:48.693000000",
        "uniqueQualifier": "-12456"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "DELETE_ROLE",
    "parameters": {
        "ROLE_ID": "567890",
        "ROLE_NAME": "CustomAdminRoleName"
    },
    "type": "DELEGATED_ADMIN_SETTINGS"
})
workspace_admin_custom_role_new_custom_role_created = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "123456"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 02:57:48.693000000",
        "uniqueQualifier": "-12456"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_ROLE",
    "parameters": {
        "ROLE_ID": "567890",
        "ROLE_NAME": "CustomAdminRoleName"
    },
    "type": "DELEGATED_ADMIN_SETTINGS"
})
workspace_admin_custom_role_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
doc_ownership_transfer_ownership_transferred_within_organization = json.dumps({
    "id": {
        "applicationName": "admin"
    },
    "name": "TRANSFER_DOCUMENT_OWNERSHIP",
    "parameters": {
        "NEW_VALUE": "homer.simpson@example.com"
    }
})
doc_ownership_transfer_document_transferred_to_external_user = json.dumps({
    "id": {
        "applicationName": "admin"
    },
    "name": "TRANSFER_DOCUMENT_OWNERSHIP",
    "parameters": {
        "NEW_VALUE": "monty.burns@badguy.com"
    }
})
workspace_password_enforce_strong_disabled_workspace_admin_disabled_strong_password_enforcement = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "110111111111111111111"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:33:56.306000000",
        "uniqueQualifier": "-6444444444444444444"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "enterprise",
        "APPLICATION_NAME": "Security",
        "NEW_VALUE": "off",
        "OLD_VALUE": "on",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "Password Management - Enforce strong password"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_password_enforce_strong_disabled_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_ONLY_ACCESS",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_password_enforce_strong_disabled_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
google_access_normal_login_event = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "type": "login"
})
google_access_resource_accessed_by_google = json.dumps({
    "id": {
        "applicationName": "access_transparency"
    },
    "type": "GSUITE_RESOURCE"
})
passthrough_rule_non_triggered_rule = json.dumps({
    "id": {
        "applicationName": "rules"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "parameters": {
        "severity": "HIGH",
        "triggered_actions": None
    }
})
passthrough_rule_high_severity_rule = json.dumps({
    "id": {
        "applicationName": "rules"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "parameters": {
        "data_source": "DRIVE",
        "severity": "HIGH",
        "triggered_actions": [
            {
                "action_type": "DRIVE_UNFLAG_DOCUMENT"
            }
        ]
    }
})
passthrough_rule_medium_severity_rule = json.dumps({
    "id": {
        "applicationName": "rules"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "parameters": {
        "data_source": "DRIVE",
        "severity": "MEDIUM",
        "triggered_actions": [
            {
                "action_type": "DRIVE_UNFLAG_DOCUMENT"
            }
        ]
    }
})
passthrough_rule_low_severity_rule = json.dumps({
    "id": {
        "applicationName": "rules"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "parameters": {
        "severity": "LOW",
        "triggered_actions": [
            {
                "action_type": "DRIVE_UNFLAG_DOCUMENT"
            }
        ]
    }
})
passthrough_rule_high_severity_rule_with_rule_name = json.dumps({
    "id": {
        "applicationName": "rules"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "parameters": {
        "severity": "HIGH",
        "rule_name": "CEO Impersonation",
        "triggered_actions": [
            {
                "action_type": "MAIL_MARK_AS_PHISHING"
            }
        ]
    }
})
group_banned_user_user_added = json.dumps({
    "id": {
        "applicationName": "groups_enterprise"
    },
    "actor": {
        "email": "homer.simpson@example.com"
    },
    "type": "moderator_action",
    "name": "add_member"
})
group_banned_user_user_banned_from_group = json.dumps({
    "id": {
        "applicationName": "groups_enterprise"
    },
    "actor": {
        "email": "homer.simpson@example.com"
    },
    "type": "moderator_action",
    "name": "ban_user_with_moderation"
})
workspace_apps_marketplace_allowlist_parameters_json_key_set_to_None_value = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "111111111111111111111"
    },
    "id": {
        "applicationName": "user_accounts",
        "customerId": "C00000000",
        "time": "2022-12-29 22:42:44.467000000",
        "uniqueQualifier": "517500000000000000"
    },
    "parameters": None,
    "ipAddress": "2600:2600:2600:2600:2600:2600:2600:2600",
    "kind": "admin#reports#activity",
    "name": "recovery_email_edit",
    "type": "recovery_info_change"
})
workspace_apps_marketplace_allowlist_change_email_setting = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-10 23:38:45.125000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_EMAIL_SETTING",
    "parameters": {
        "NEW_VALUE": "3",
        "OLD_VALUE": "2",
        "ORG_UNIT_NAME": "EXAMPLE IO",
        "SETTING_NAME": "ENABLE_G_SUITE_MARKETPLACE"
    },
    "type": "EMAIL_SETTINGS"
})
workspace_apps_marketplace_allowlist_change_email_setting_default = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D1234",
        "time": "2022-12-10 23:33:04.667000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_EMAIL_SETTING",
    "parameters": {
        "NEW_VALUE": "1",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "EXAMPLE IO",
        "SETTING_NAME": "ENABLE_G_SUITE_MARKETPLACE"
    },
    "type": "EMAIL_SETTINGS"
})
workspace_apps_marketplace_allowlist_new_custom_role_created = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "123456"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 02:57:48.693000000",
        "uniqueQualifier": "-12456"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_ROLE",
    "parameters": {
        "ROLE_ID": "567890",
        "ROLE_NAME": "CustomAdminRoleName"
    },
    "type": "DELEGATED_ADMIN_SETTINGS"
})
workspace_apps_marketplace_allowlist_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
mobile_device_suspicious_activity_normal_mobile_event = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "DEVICE_SYNC_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io"
    }
})
mobile_device_suspicious_activity_suspicious_activity = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "SUSPICIOUS_ACTIVITY_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io"
    }
})
permissions_delegated_other_admin_action = json.dumps({
    "id": {
        "applicationName": "admin"
    },
    "type": "DELEGATED_ADMIN_SETTINGS",
    "name": "RENAME_ROLE",
    "parameters": {
        "ROLE_NAME": "Vault Admins",
        "USER_EMAIL": "homer.simpson@example.com"
    }
})
permissions_delegated_privileges_assigned = json.dumps({
    "id": {
        "applicationName": "admin"
    },
    "type": "DELEGATED_ADMIN_SETTINGS",
    "name": "ASSIGN_ROLE",
    "parameters": {
        "ROLE_NAME": "Vault Admins",
        "USER_EMAIL": "homer.simpson@example.com"
    }
})
brute_force_login_failed_login = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "type": "login",
    "name": "login_failure"
})
brute_force_login_successful_login = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "type": "login",
    "name": "login_success"
})
brute_force_login_other_login_event = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "type": "login",
    "name": "login_verification"
})
external_forwarding_forwarding_to_external_address = json.dumps({
    "id": {
        "applicationName": "user_accounts",
        "customerId": "D12345"
    },
    "actor": {
        "email": "homer.simpson@.springfield.io"
    },
    "type": "email_forwarding_change",
    "name": "email_forwarding_out_of_domain",
    "parameters": {
        "email_forwarding_destination_address": "HSimpson@gmail.com"
    }
})
external_forwarding_forwarding_to_external_address___allowed_domain = json.dumps({
    "id": {
        "applicationName": "user_accounts",
        "customerId": "D12345"
    },
    "actor": {
        "email": "homer.simpson@.springfield.io"
    },
    "type": "email_forwarding_change",
    "name": "email_forwarding_out_of_domain",
    "parameters": {
        "email_forwarding_destination_address": "HSimpson@example.com"
    }
})
external_forwarding_non_forwarding_event = json.dumps({
    "id": {
        "applicationName": "user_accounts",
        "customerId": "D12345"
    },
    "actor": {
        "email": "homer.simpson@.springfield.io"
    },
    "type": "2sv_change",
    "name": "2sv_enroll"
})
external_forwarding_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
login_type_login_with_approved_type = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "type": "login",
    "name": "login_success",
    "parameters": {
        "login_type": "saml"
    }
})
login_type_login_with_unapproved_type = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "type": "login",
    "name": "login_success",
    "parameters": {
        "login_type": "turbo-snail"
    }
})
login_type_non_login_event = json.dumps({
    "id": {
        "applicationName": "logout"
    },
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "type": "login",
    "name": "login_success",
    "parameters": {
        "login_type": "saml"
    }
})
login_type_saml_login_event = json.dumps({
    "actor": {
        "email": "some.user@somedomain.com"
    },
    "id": {
        "applicationName": "saml",
        "time": "2022-05-26 15:26:09.421000000"
    },
    "ipAddress": "10.10.10.10",
    "kind": "admin#reports#activity",
    "name": "login_success",
    "parameters": {
        "application_name": "Some SAML Application",
        "initiated_by": "sp",
        "orgunit_path": "/SomeOrgUnit",
        "saml_status_code": "SUCCESS_URI"
    },
    "type": "login"
})
calendar_made_public_user_publically_shared_a_calendar = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "110111111111111111111"
    },
    "id": {
        "applicationName": "calendar",
        "customerId": "D12345",
        "time": "2022-12-10 22:33:31.852000000",
        "uniqueQualifier": "-2888888888888888888"
    },
    "ipAddress": "1.2.3.4",
    "kind": "admin#reports#activity",
    "name": "change_calendar_acls",
    "ownerDomain": "example.io",
    "parameters": {
        "access_level": "freebusy",
        "api_kind": "web",
        "calendar_id": "user@example.io",
        "grantee_email": "__public_principal__@public.calendar.google.com",
        "user_agent": "Mozilla/5.0"
    },
    "type": "calendar_change"
})
calendar_made_public_admin_set_default_calendar_sharing_outside_domain_setting_to_read_write_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_WRITE_ACCESS",
        "OLD_VALUE": "READ_ONLY_ACCESS",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
calendar_made_public_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
workspace_advanced_protection_program_parameters_json_key_set_to_None_value = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "111111111111111111111"
    },
    "id": {
        "applicationName": "user_accounts",
        "customerId": "C00000000",
        "time": "2022-12-29 22:42:44.467000000",
        "uniqueQualifier": "517500000000000000"
    },
    "parameters": None,
    "ipAddress": "2600:2600:2600:2600:2600:2600:2600:2600",
    "kind": "admin#reports#activity",
    "name": "recovery_email_edit",
    "type": "recovery_info_change"
})
workspace_advanced_protection_program_allow_security_codes = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:35:29.906000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "standard",
        "APPLICATION_NAME": "Security",
        "NEW_VALUE": "ALLOWED_WITH_REMOTE_ACCESS",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "Advanced Protection Program Settings - Allow security codes"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_advanced_protection_program_enable_user_enrollment = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:35:29.906000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "standard",
        "APPLICATION_NAME": "Security",
        "NEW_VALUE": "True",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "Advanced Protection Program Settings - Enable user enrollment"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_advanced_protection_program_new_custom_role_created = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "123456"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 02:57:48.693000000",
        "uniqueQualifier": "-12456"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CREATE_ROLE",
    "parameters": {
        "ROLE_ID": "567890",
        "ROLE_NAME": "CustomAdminRoleName"
    },
    "type": "DELEGATED_ADMIN_SETTINGS"
})
workspace_advanced_protection_program_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
user_suspended_normal_login_event = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "kind": "admin#reports#activity",
    "type": "account_warning",
    "name": "login_success",
    "parameters": {
        "affected_email_address": "bobert@ext.runpanther.io"
    }
})
user_suspended_account_warning_not_for_user_suspended = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "kind": "admin#reports#activity",
    "type": "account_warning",
    "name": "suspicious_login ",
    "parameters": {
        "affected_email_address": "bobert@ext.runpanther.io"
    }
})
user_suspended_account_warning_for_suspended_user = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "kind": "admin#reports#activity",
    "type": "account_warning",
    "name": "account_disabled_spamming",
    "parameters": {
        "affected_email_address": "bobert@ext.runpanther.io"
    }
})
advanced_protection_advanced_protection_enabled = json.dumps({
    "id": {
        "applicationName": "user_accounts"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.com"
    },
    "type": "titanium_change",
    "name": "titanium_enroll"
})
advanced_protection_advanced_protection_disabled = json.dumps({
    "id": {
        "applicationName": "user_accounts"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.com"
    },
    "type": "titanium_change",
    "name": "titanium_unenroll"
})
workspace_password_reuse_enabled_workspace_admin_enabled_password_reuse = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:18:47.973000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "standard",
        "APPLICATION_NAME": "Security",
        "NEW_VALUE": "True",
        "OLD_VALUE": "False",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "Password Management - Enable password reuse"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_password_reuse_enabled_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_ONLY_ACCESS",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_password_reuse_enabled_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
workspace_trusted_domains_allowlist_workspace_admin_remove_trusted_domain = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "110506209185950390992"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 00:01:34.643000000",
        "uniqueQualifier": "-2972206985263071668"
    },
    "kind": "admin#reports#activity",
    "name": "REMOVE_TRUSTED_DOMAINS",
    "p_source_label": "Staging",
    "parameters": {
        "DOMAIN_NAME": "evilexample.com"
    },
    "type": "DOMAIN_SETTINGS"
})
workspace_trusted_domains_allowlist_workspace_admin_add_trusted_domain = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "110506209185950390992"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-10 23:59:24.470000000",
        "uniqueQualifier": "-334478670839567761"
    },
    "kind": "admin#reports#activity",
    "name": "ADD_TRUSTED_DOMAINS",
    "parameters": {
        "DOMAIN_NAME": "evilexample.com"
    },
    "type": "DOMAIN_SETTINGS"
})
workspace_trusted_domains_allowlist_admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "MANAGE_ACCESS",
        "OLD_VALUE": "READ_WRITE_ACCESS",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_trusted_domains_allowlist_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
workspace_gmail_security_sandbox_disabled_workspace_admin_disables_security_sandbox = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 03:31:41.212000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "enterprise",
        "APPLICATION_NAME": "Gmail",
        "NEW_VALUE": "False",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "AttachmentDeepScanningSettingsProto deep_scanning_enabled"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_gmail_security_sandbox_disabled_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_ONLY_ACCESS",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_gmail_security_sandbox_disabled_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
workspace_data_export_created_workspace_admin_data_export_created = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "admin@example.io",
        "profileId": "11011111111111111111111"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-10 22:21:40.079000000",
        "uniqueQualifier": "-2833899999999999999"
    },
    "kind": "admin#reports#activity",
    "name": "CUSTOMER_TAKEOUT_CREATED",
    "parameters": {
        "OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID": "00mmmmmmmmmmmmm"
    },
    "type": "CUSTOMER_TAKEOUT"
})
workspace_data_export_created_workspace_admin_data_export_succeeded = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "admin@example.io",
        "profileId": "11011111111111111111111"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-12 22:21:40.106000000",
        "uniqueQualifier": "3005999999999999999"
    },
    "kind": "admin#reports#activity",
    "name": "CUSTOMER_TAKEOUT_SUCCEEDED",
    "parameters": {
        "OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID": "00mmmmmmmmmmmmm"
    },
    "type": "CUSTOMER_TAKEOUT"
})
workspace_data_export_created_admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "MANAGE_ACCESS",
        "OLD_VALUE": "READ_WRITE_ACCESS",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_data_export_created_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
two_step_verification_two_step_verification_enabled = json.dumps({
    "id": {
        "applicationName": "user_accounts"
    },
    "actor": {
        "callerType": "USER",
        "email": "some.user@somedomain.com"
    },
    "kind": "admin#reports#activity",
    "type": "2sv_change",
    "name": "2sv_enroll"
})
two_step_verification_two_step_verification_disabled = json.dumps({
    "id": {
        "applicationName": "user_accounts"
    },
    "actor": {
        "callerType": "USER",
        "email": "some.user@somedomain.com"
    },
    "kind": "admin#reports#activity",
    "type": "2sv_change",
    "name": "2sv_disable"
})
leaked_password_normal_login_event = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "type": "login",
    "name": "logout",
    "parameters": {
        "login_type": "saml"
    }
})
leaked_password_account_warning_not_for_password_leaked = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "type": "account_warning",
    "name": "account_disabled_spamming",
    "parameters": {
        "affected_email_address": "homer.simpson@example.com"
    }
})
leaked_password_account_warning_for_password_leaked = json.dumps({
    "id": {
        "applicationName": "login"
    },
    "type": "account_warning",
    "name": "account_disabled_password_leak",
    "parameters": {
        "affected_email_address": "homer.simpson@example.com"
    }
})
workspace_calendar_external_sharing_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_ONLY_ACCESS",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_calendar_external_sharing_admin_set_default_calendar_sharing_outside_domain_setting_to_read_write_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_WRITE_ACCESS",
        "OLD_VALUE": "READ_ONLY_ACCESS",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_calendar_external_sharing_admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "MANAGE_ACCESS",
        "OLD_VALUE": "READ_WRITE_ACCESS",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_calendar_external_sharing_non_default_calendar_sharing_outside_domain_event = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "user@example.io",
        "profileId": "111111111111111111111"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-12 22:21:40.106000000",
        "uniqueQualifier": "1000000000000000000"
    },
    "kind": "admin#reports#activity",
    "name": "CUSTOMER_TAKEOUT_SUCCEEDED",
    "parameters": {
        "OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID": "00mmmmmmmmmmmmm"
    },
    "type": "CUSTOMER_TAKEOUT"
})
workspace_calendar_external_sharing_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
workspace_gmail_enhanced_predelivery_scanning_workspace_admin_disables_enhanced_pre_delivery_scanning = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 03:42:54.859000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_APPLICATION_SETTING",
    "parameters": {
        "APPLICATION_EDITION": "business_plus_2021",
        "APPLICATION_NAME": "Gmail",
        "NEW_VALUE": "True",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
    },
    "type": "APPLICATION_SETTINGS"
})
workspace_gmail_enhanced_predelivery_scanning_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-11 01:06:26.303000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_CALENDAR_SETTING",
    "parameters": {
        "DOMAIN_NAME": "example.io",
        "NEW_VALUE": "READ_ONLY_ACCESS",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "Example IO",
        "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN"
    },
    "type": "CALENDAR_SETTINGS"
})
workspace_gmail_enhanced_predelivery_scanning_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})
mobile_device_compromise_normal_mobile_event = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "DEVICE_REGISTER_UNREGISTER_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io"
    }
})
mobile_device_compromise_suspicious_activity_shows_not_compromised = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "DEVICE_COMPROMISED_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io",
        "DEVICE_COMPROMISED_STATE": "NOT_COMPROMISED"
    }
})
mobile_device_compromise_suspicious_activity_shows_compromised = json.dumps({
    "id": {
        "applicationName": "mobile"
    },
    "actor": {
        "callerType": "USER",
        "email": "homer.simpson@example.io"
    },
    "type": "device_updates",
    "name": "DEVICE_COMPROMISED_EVENT",
    "parameters": {
        "USER_EMAIL": "homer.simpson@example.io",
        "DEVICE_COMPROMISED_STATE": "COMPROMISED"
    }
})
workspace_apps_marketplace_new_domain_application_change_email_setting_default = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D1234",
        "time": "2022-12-10 23:33:04.667000000",
        "uniqueQualifier": "-12345"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "CHANGE_EMAIL_SETTING",
    "parameters": {
        "NEW_VALUE": "1",
        "OLD_VALUE": "DEFAULT",
        "ORG_UNIT_NAME": "EXAMPLE IO",
        "SETTING_NAME": "ENABLE_G_SUITE_MARKETPLACE"
    },
    "type": "EMAIL_SETTINGS"
})
workspace_apps_marketplace_new_domain_application_docusign_for_google = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-10 23:05:39.508000000",
        "uniqueQualifier": "-12345"
    },
    "kind": "admin#reports#activity",
    "name": "ADD_APPLICATION",
    "parameters": {
        "APP_ID": "469176070494",
        "APPLICATION_ENABLED": "True",
        "APPLICATION_NAME": "DocuSign eSignature for Google"
    },
    "type": "DOMAIN_SETTINGS"
})
workspace_apps_marketplace_new_domain_application_microsoft_apps_for_google = json.dumps({
    "actor": {
        "callerType": "USER",
        "email": "example@example.io",
        "profileId": "12345"
    },
    "id": {
        "applicationName": "admin",
        "customerId": "D12345",
        "time": "2022-12-10 23:05:39.508000000",
        "uniqueQualifier": "-12345"
    },
    "kind": "admin#reports#activity",
    "name": "ADD_APPLICATION",
    "parameters": {
        "APP_ID": "469176070494",
        "APPLICATION_ENABLED": "True",
        "APPLICATION_NAME": "Microsoft Applications for Google"
    },
    "type": "DOMAIN_SETTINGS"
})
workspace_apps_marketplace_new_domain_application_listobject_type = json.dumps({
    "actor": {
        "email": "user@example.io",
        "profileId": "118111111111111111111"
    },
    "id": {
        "applicationName": "drive",
        "customerId": "D12345",
        "time": "2022-12-20 17:27:47.080000000",
        "uniqueQualifier": "-7312729053723258069"
    },
    "ipAddress": "12.12.12.12",
    "kind": "admin#reports#activity",
    "name": "rename",
    "parameters": {
        "actor_is_collaborator_account": None,
        "billable": True,
        "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
        "doc_title": "Document Title- Found Here",
        "doc_type": "presentation",
        "is_encrypted": None,
        "new_value": [
            "Document Title- Found Here"
        ],
        "old_value": [
            "Document Title- Old"
        ],
        "owner": "user@example.io",
        "owner_is_shared_drive": None,
        "owner_is_team_drive": None,
        "primary_event": True,
        "visibility": "private"
    },
    "type": "access"
})


login_failure = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {
            "email": "some.user@somedomain.com",
        },
        "type": "login",
        "name": "login_failure",
    }
)

user_publicly_shared_calendar = json.dumps(
    {
        "actor": {"email": "user@example.io", "profileId": "110111111111111111111"},
        "id": {
            "applicationName": "calendar",
            "customerId": "D12345",
            "time": "2022-12-10 22:33:31.852000000",
            "uniqueQualifier": "-2888888888888888888",
        },
        "ipAddress": "1.2.3.4",
        "kind": "admin#reports#activity",
        "name": "change_calendar_acls",
        "ownerDomain": "example.io",
        "parameters": {
            "access_level": "freebusy",
            "api_kind": "web",
            "calendar_id": "user@example.io",
            "grantee_email": "__public_principal__@public.calendar.google.com",
            "user_agent": "Mozilla/5.0",
        },
        "type": "calendar_change",
    }
)

admin_set_default_cal_setting = json.dumps(
    {
        "actor": {"callerType": "USER", "email": "example@example.io", "profileId": "12345"},
        "id": {
            "applicationName": "admin",
            "customerId": "D12345",
            "time": "2022-12-11 01:06:26.303000000",
            "uniqueQualifier": "-12345",
        },
        "ipAddress": "12.12.12.12",
        "kind": "admin#reports#activity",
        "name": "CHANGE_CALENDAR_SETTING",
        "parameters": {
            "DOMAIN_NAME": "example.io",
            "NEW_VALUE": "READ_WRITE_ACCESS",
            "OLD_VALUE": "READ_ONLY_ACCESS",
            "ORG_UNIT_NAME": "Example IO",
            "SETTING_NAME": "SHARING_OUTSIDE_DOMAIN",
        },
        "type": "CALENDAR_SETTINGS",
    }
)

list_object_type = json.dumps(
    {
        "actor": {"email": "user@example.io", "profileId": "118111111111111111111"},
        "id": {
            "applicationName": "drive",
            "customerId": "D12345",
            "time": "2022-12-20 17:27:47.080000000",
            "uniqueQualifier": "-7312729053723258069",
        },
        "ipAddress": "12.12.12.12",
        "kind": "admin#reports#activity",
        "name": "rename",
        "parameters": {
            "actor_is_collaborator_account": None,
            "billable": True,
            "doc_id": "1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
            "doc_title": "Document Title- Found Here",
            "doc_type": "presentation",
            "is_encrypted": None,
            "new_value": ["Document Title- Found Here"],
            "old_value": ["Document Title- Old"],
            "owner": "user@example.io",
            "owner_is_shared_drive": None,
            "owner_is_team_drive": None,
            "primary_event": True,
            "visibility": "private",
        },
        "type": "access",
    }
)

access_event = json.dumps(
    {
        "p_row_id": "111222",
        "actor": {"email": "bobert@example.com"},
        "id": {"applicationName": "drive"},
        "events": [{"type": "access", "name": "download"}],
    }
)

modify_event_without_over_visibility = json.dumps(
    {
        "p_row_id": "111222",
        "actor": {"email": "bobert@example.com"},
        "id": {"applicationName": "drive"},
        "events": [{"type": "access", "name": "edit", "parameters": [{"name": "visibility", "value": "private"}]}],
    }
)

overly_visible_doc_modified = json.dumps(
    {
        "p_row_id": "111222",
        "actor": {"email": "bobert@example.com"},
        "id": {"applicationName": "drive"},
        "events": [
            {
                "type": "access",
                "name": "edit",
                "parameters": [
                    {"name": "visibility", "value": "people_with_link"},
                    {"name": "doc_title", "value": "my shared document"},
                ],
            }
        ],
    }
)

normal_login = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {
            "email": "homer.simpson@example.com",
        },
        "type": "login",
        "name": "login_success",
        "parameters": {
            "is_suspicious": "None",
            "login_challenge_method": ["none"],
        },
    }
)

gov_backed_warning = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {
            "email": "homer.simpson@example.com",
        },
        "type": "login",
        "name": "gov_attack_warning",
        "parameters": {
            "is_suspicious": "None",
            "login_challenge_method": ["none"],
        },
    }
)

normal_mobile_event = json.dumps(
    {
        "id": {
            "applicationName": "mobile",
        },
        "actor": {
            "callerType": "USER",
            "email": "homer.simpson@example.io",
        },
        "type": "device_updates",
        "name": "DEVICE_SYNC_EVENT",
        "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
    }
)

suspicious_activity = json.dumps(
    {
        "id": {
            "applicationName": "mobile",
        },
        "actor": {
            "callerType": "USER",
            "email": "homer.simpson@example.io",
        },
        "type": "device_updates",
        "name": "SUSPICIOUS_ACTIVITY_EVENT",
        "parameters": {"USER_EMAIL": "homer.simpson@example.io"},
    }
)

advanced_protection_enabled = json.dumps(
    {
        "id": {
            "applicationName": "user_accounts",
        },
        "actor": {"callerType": "USER", "email": "homer.simpson@example.com"},
        "type": "titanium_change",
        "name": "titanium_enroll",
    }
)

advanced_protection_disabled = json.dumps(
    {
        "id": {
            "applicationName": "user_accounts",
        },
        "actor": {"callerType": "USER", "email": "homer.simpson@example.com"},
        "type": "titanium_change",
        "name": "titanium_unenroll",
    }
)

non_triggered_rule = json.dumps(
    {
        "id": {"applicationName": "rules"},
        "actor": {"email": "some.user@somedomain.com"},
        "parameters": {"severity": "HIGH", "triggered_actions": None},
    }
)

high_severity_rule = json.dumps(
    {
        "id": {"applicationName": "rules"},
        "actor": {"email": "some.user@somedomain.com"},
        "parameters": {
            "data_source": "DRIVE",
            "severity": "HIGH",
            "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
        },
    }
)

medium_severity_rule = json.dumps(
    {
        "id": {"applicationName": "rules"},
        "actor": {"email": "some.user@somedomain.com"},
        "parameters": {
            "data_source": "DRIVE",
            "severity": "MEDIUM",
            "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}],
        },
    }
)

low_severity_rule = json.dumps(
    {
        "id": {"applicationName": "rules"},
        "actor": {"email": "some.user@somedomain.com"},
        "parameters": {"severity": "LOW", "triggered_actions": [{"action_type": "DRIVE_UNFLAG_DOCUMENT"}]},
    }
)

high_severity_rule_with_rule_name = json.dumps(
    {
        "id": {"applicationName": "rules"},
        "actor": {"email": "some.user@somedomain.com"},
        "parameters": {
            "severity": "HIGH",
            "rule_name": "CEO Impersonation",
            "triggered_actions": [{"action_type": "MAIL_MARK_AS_PHISHING"}],
        },
    }
)

login_with_approved_type = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {"email": "some.user@somedomain.com"},
        "type": "login",
        "name": "login_success",
        "parameters": {"login_type": "saml"},
    }
)

login_with_unapproved_type = json.dumps(
    {
        "id": {
            "applicationName": "login",
        },
        "actor": {"email": "some.user@somedomain.com"},
        "type": "login",
        "name": "login_success",
        "parameters": {"login_type": "turbo-snail"},
    }
)

non_login_event = json.dumps(
    {
        "id": {
            "applicationName": "logout",
        },
        "actor": {"email": "some.user@somedomain.com"},
        "type": "login",
        "name": "login_success",
        "parameters": {"login_type": "saml"},
    }
)

saml_login_event = json.dumps(
    {
        "actor": {
            "email": "some.user@somedomain.com",
        },
        "id": {
            "applicationName": "saml",
            "time": "2022-05-26 15:26:09.421000000",
        },
        "ipAddress": "10.10.10.10",
        "kind": "admin#reports#activity",
        "name": "login_success",
        "parameters": {
            "application_name": "Some SAML Application",
            "initiated_by": "sp",
            "orgunit_path": "/SomeOrgUnit",
            "saml_status_code": "SUCCESS_URI",
        },
        "type": "login",
    }
)

dangerous_share_of_known_doc_with_a_missing_user = json.dumps(
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2020-09-07T15:50:49.617Z",
            "uniqueQualifier": "1111111111111111111",
            "applicationName": "drive",
            "customerId": "C010qxghg",
        },
        "actor": {"email": "example@acme.com", "profileId": "1111111111111111111"},
        "events": [
            {
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": [
                    {"name": "primary_event", "boolValue": True},
                    {"name": "visibility_change", "value": "external"},
                    {"name": "target_user", "value": "outside@acme.com"},
                    {"name": "old_visibility", "value": "private"},
                    {"name": "doc_id", "value": "1111111111111111111"},
                    {"name": "doc_type", "value": "document"},
                    {"name": "doc_title", "value": "Document Title Primary"},
                    {"name": "visibility", "value": "shared_externally"},
                    {"name": "originating_app_id", "value": "1111111111111111111"},
                    {"name": "owner_is_shared_drive", "boolValue": False},
                    {"name": "owner_is_team_drive", "boolValue": False},
                    {"name": "old_value", "multiValue": ["none"]},
                    {"name": "new_value", "multiValue": ["can_edit"]},
                ],
            }
        ],
    }
)

dangerous_share_of_unknown_doc = json.dumps(
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2020-09-07T15:50:49.617Z",
            "uniqueQualifier": "1111111111111111111",
            "applicationName": "drive",
            "customerId": "C010qxghg",
        },
        "actor": {"email": "example@acme.com", "profileId": "1111111111111111111"},
        "events": [
            {
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": [
                    {"name": "primary_event", "boolValue": True},
                    {"name": "visibility_change", "value": "external"},
                    {"name": "target_user", "value": "alice@external.com"},
                    {"name": "old_visibility", "value": "private"},
                    {"name": "doc_id", "value": "1111111111111111111"},
                    {"name": "doc_type", "value": "document"},
                    {"name": "doc_title", "value": "Untitled document"},
                    {"name": "visibility", "value": "shared_externally"},
                    {"name": "originating_app_id", "value": "1111111111111111111"},
                    {"name": "owner_is_shared_drive", "boolValue": False},
                    {"name": "owner_is_team_drive", "boolValue": False},
                    {"name": "old_value", "multiValue": ["none"]},
                    {"name": "new_value", "multiValue": ["can_edit"]},
                ],
            }
        ],
    }
)

share_allowed_by_exception = json.dumps(
    {
        "kind": "admin#reports#activity",
        "id": {
            "time": "2020-07-07T15:50:49.617Z",
            "uniqueQualifier": "1111111111111111111",
            "applicationName": "drive",
            "customerId": "C010qxghg",
        },
        "actor": {"email": "alice@acme.com", "profileId": "1111111111111111111"},
        "events": [
            {
                "type": "acl_change",
                "name": "change_user_access",
                "parameters": [
                    {"name": "primary_event", "boolValue": True},
                    {"name": "billable", "boolValue": True},
                    {"name": "visibility_change", "value": "external"},
                    {"name": "target_domain", "value": "acme.com"},
                    {"name": "old_visibility", "value": "private"},
                    {"name": "doc_id", "value": "1111111111111111111"},
                    {"name": "doc_type", "value": "document"},
                    {"name": "doc_title", "value": "Document Title Pattern"},
                    {"name": "visibility", "value": "shared_externally"},
                    {"name": "originating_app_id", "value": "1111111111111111111"},
                    {"name": "owner_is_shared_drive", "boolValue": False},
                    {"name": "owner_is_team_drive", "boolValue": False},
                    {"name": "old_value", "multiValue": ["none"]},
                    {"name": "new_value", "multiValue": [
                        "people_within_domain_with_link"]},
                ],
            }
        ],
    }
)

normal_login_event = json.dumps(
    {"id": {"applicationName": "login"}, "type": "login",
        "name": "logout", "parameters": {"login_type": "saml"}}
)
account_warning_not_for_password_leaked = json.dumps(
    {
        "id": {"applicationName": "login"},
        "type": "account_warning",
        "name": "account_disabled_spamming",
        "parameters": {"affected_email_address": "homer.simpson@example.com"},
    }
)
account_warning_for_password_leaked = json.dumps(
    {
        "id": {"applicationName": "login"},
        "type": "account_warning",
        "name": "account_disabled_password_leak",
        "parameters": {"affected_email_address": "homer.simpson@example.com"},
    }
)
small_number_of_failed_logins = json.dumps(
    {
        "id": {"applicationName": "mobile"},
        "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
        "type": "device_updates",
        "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
        "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": 2},
    }
)
multiple_failed_login_attempts_with_string_type = json.dumps(
    {
        "id": {"applicationName": "mobile"},
        "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
        "type": "device_updates",
        "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
        "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": "100"},
    }
)
multiple_failed_login_attempts_with_int_type = json.dumps(
    {
        "id": {"applicationName": "mobile"},
        "actor": {"callerType": "USER", "email": "homer.simpson@example.io"},
        "type": "device_updates",
        "name": "FAILED_PASSWORD_ATTEMPTS_EVENT",
        "parameters": {"USER_EMAIL": "homer.simpson@example.io", "FAILED_PASSWD_ATTEMPTS": 100},
    }
)


forwarding_to_external_address = json.dumps(
    {
        "id": {
            "applicationName": "user_accounts",
            "customerId": "D12345",
        },
        "actor": {
            "email": "homer.simpson@.springfield.io",
        },
        "type": "email_forwarding_change",
        "name": "email_forwarding_out_of_domain",
        "parameters": {"email_forwarding_destination_address": "HSimpson@gmail.com"},
    }
)
