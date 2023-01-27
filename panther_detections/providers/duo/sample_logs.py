import json
generic_skey_view = json.dumps({
    "action": "integration_skey_view",
    "isotimestamp": "2022-12-14 20:09:57",
    "object": "Example Integration Name",
    "timestamp": "2022-12-14 20:09:57",
    "username": "Homer Simpson"
})
user_marked_fraud = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {
        "key": "D12345",
        "name": "Slack"
    },
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "user_marked_fraud",
    "result": "fraud",
    "user": {
        "name": "example@example.io"
    }
})
good_auth = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {
        "key": "D12345",
        "name": "Slack"
    },
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "user_approved",
    "result": "success",
    "user": {
        "name": "example@example.io"
    }
})
admin_mfa_update_event = json.dumps({
    "action": "update_admin_factor_restrictions",
    "description": "{\"allowed_factors\": \"Duo mobile passcodes, Hardware tokens, Duo push, Yubikey aes\"}",
    "isotimestamp": "2022-02-21 21:48:06",
    "timestamp": "2022-02-21 21:48:06",
    "username": "Homer Simpson"
})
duo_app_install_ = json.dumps({
    "action": "application_install",
    "isotimestamp": "2022-12-14 20:09:57",
    "object": "Example Integration Name",
    "timestamp": "2022-12-14 20:09:57",
    "username": "Homer Simpson"
})
different_admin_action = json.dumps({
    "action": "admin_update",
    "description": "{}",
    "isotimestamp": "2022-12-14 20:11:53",
    "timestamp": "2022-12-14 20:11:53",
    "username": "John P. Admin"
})
endpoint_is_not_trusted = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {},
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "endpoint_is_not_trusted",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
bypass_create = json.dumps({
    "action": "bypass_create",
    "description": "{\"bypass\": \"\", \"count\": 1, \"valid_secs\": 3600, \"auto_generated\": true, \"remaining_uses\": 1, \"user_id\": \"D12345\", \"bypass_code_ids\": [\"A12345\"]}",
    "isotimestamp": "2022-12-14 21:17:39",
    "object": "target@example.io",
    "timestamp": "2022-12-14 21:17:39",
    "username": "Homer Simpson"
})
sso_update = json.dumps({
    "action": "admin_single_sign_on_update",
    "description": "{\"sso_url\": \"https://duff.okta.com/app/duoadminpanel/abcdefghijklm/sso/saml\", \"slo_url\": null, \"idp_type\": \"okta\", \"cert\": \"C=US/CN=duff/L=Springfield/O=Okta/OU=SSOProvider/ST=California/emailAddress=info@okta.com - 2031-08-10 13:39:00+00:00\", \"require_signed_response\": true, \"entity_id\": \"http://www.okta.com/abcdefghijk\"}",
    "isotimestamp": "2021-10-12 21:33:40",
    "timestamp": "2021-10-12 21:33:40",
    "username": "Homer Simpson"
})
policy_update = json.dumps({
    "action": "policy_update",
    "description": "{\"adaptive_auth_display_unit\": \"days\", \"trusted_mobile_endpoint_policy\": \"no action\", \"adaptive_auth_hours\": 0, \"admin_email\": \"homer.simpson@simpsons.com\", \"allow_factor_u2f\": false, \"device_certificate_policy\": \"no action\", \"allow_factor_phone\": false, \"local_trusted_sessions_display_val\": 0, \"allow_adaptive_auth\": false, \"local_trusted_sessions_display_unit\": \"days\", \"allow_factor_sms\": false}",
    "isotimestamp": "2022-02-21 21:48:48",
    "object": "Global Policy",
    "timestamp": "2022-02-21 21:48:48",
    "username": "Homer Simpson"
})
admin_lockout__invalid_json = json.dumps({
    "action": "admin_lockout",
    "description": "\"message\": \"Admin temporarily locked out due to too many passcode attempts.\"",
    "isotimestamp": "2022-12-14 21:02:03",
    "timestamp": "2022-12-14 21:02:03",
    "username": "Homer Simpson"
})
admin_create = json.dumps({
    "action": "admin_create",
    "description": "{\"name\": \"Homer Simpson\", \"phone\": null, \"is_temporary_password\": false, \"email\": \"homer.simpson@simpsons.com\", \"hardtoken\": null, \"role\": \"Owner\", \"status\": \"Pending Activation\", \"restricted_by_admin_units\": false, \"administrative_units\": \"\"}",
    "isotimestamp": "2023-01-17 16:47:54",
    "object": "Homer Simpson",
    "timestamp": "2023-01-17 16:47:54",
    "username": "Bart Simpson"
})
marked_fraud = json.dumps({
    "action": "admin_2fa_error",
    "description": "{\"ip_address\": \"12.12.12.12\", \"email\": \"example@example.io\", \"factor\": \"push\", \"error\": \"Login request reported as fraudulent.\"}",
    "isotimestamp": "2022-12-14 20:11:53",
    "timestamp": "2022-12-14 20:11:53",
    "username": "John P. Admin"
})
admin_api_integration_created = json.dumps({
    "action": "integration_create",
    "description": "{\"greeting\": \"\", \"notes\": \"\", \"offline_auth_enabled\": 0, \"offline_max_days\": 0, \"offline_max_attempts\": 0, \"type\": \"Admin API\", \"raw_type\": \"adminapi\", \"name\": \"Admin API\", \"self_service_allowed\": false, \"username_normalization_policy\": \"None\", \"missing_web_referer_policy\": \"deny\", \"networks_for_api_access\": \"\", \"group_access\": \"\"}",
    "isotimestamp": "2021-11-30 17:15:33",
    "object": "Admin API",
    "timestamp": "2021-11-30 17:15:33",
    "username": "Homer Simpson"
})
other_event = json.dumps({
    "action": "user_update",
    "description": "{\"phones\": \"\"}",
    "isotimestamp": "2021-07-02 18:31:56",
    "object": "homer.simpson@simpsons.io",
    "timestamp": "2021-07-02 18:31:56",
    "username": "Homer Simpson"
})
enforcement_optional = json.dumps({
    "action": "admin_single_sign_on_update",
    "description": "{\"enforcement_status\": \"optional\"}",
    "isotimestamp": "2021-10-12 21:29:22",
    "timestamp": "2021-10-12 21:29:22",
    "username": "Homer Simpson"
})
bypass_view = json.dumps({
    "action": "bypass_view",
    "description": "{\"user_id\": \"D1234\", \"bypass_code_id\": \"D5678\"}",
    "isotimestamp": "2022-12-14 21:17:54",
    "object": "target@example.io",
    "timestamp": "2022-12-14 21:17:54",
    "username": "Homer Simpson"
})
enforcement_required = json.dumps({
    "action": "admin_single_sign_on_update",
    "description": "{\"enforcement_status\": \"required\"}",
    "isotimestamp": "2021-10-12 21:29:22",
    "timestamp": "2021-10-12 21:29:22",
    "username": "Homer Simpson"
})
bypass_delete = json.dumps({
    "action": "bypass_detele",
    "description": "{\"bypass\": \"\", \"count\": 1, \"valid_secs\": 3600, \"auto_generated\": true, \"remaining_uses\": 1, \"user_id\": \"D12345\", \"bypass_code_ids\": [\"A12345\"]}",
    "isotimestamp": "2022-12-14 21:17:39",
    "object": "target@example.io",
    "timestamp": "2022-12-14 21:17:39",
    "username": "Homer Simpson"
})
account_disabled = json.dumps({
    "action": "user_update",
    "description": "{\"status\": \"Disabled\"}",
    "isotimestamp": "2021-10-05 22:45:33",
    "object": "bart.simpson@simpsons.com",
    "timestamp": "2021-10-05 22:45:33",
    "username": "Homer Simpson"
})
denied_old_creds = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {
        "key": "D12345",
        "name": "Slack"
    },
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "out_of_date",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
non_admin_api_integration = json.dumps({
    "action": "integration_create",
    "description": "{\"greeting\": \"\", \"notes\": \"\", \"offline_auth_enabled\": 0, \"offline_max_days\": 0, \"offline_max_attempts\": 0, \"type\": \"1Password\", \"raw_type\": \"1password\", \"name\": \"1Password\", \"self_service_allowed\": false, \"username_normalization_policy\": \"None\", \"missing_web_referer_policy\": \"deny\", \"networks_for_api_access\": \"\", \"group_access\": \"\"}",
    "isotimestamp": "2021-11-30 17:11:51",
    "object": "1Password",
    "timestamp": "2021-11-30 17:11:51",
    "username": "Homer Simpson"
})
account_active = json.dumps({
    "action": "user_update",
    "description": "{\"status\": \"Active\"}",
    "isotimestamp": "2021-10-05 22:45:33",
    "object": "bart.simpson@simpsons.com",
    "timestamp": "2021-10-05 22:45:33",
    "username": "Homer Simpson"
})
invalid_device = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {},
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "invalid_device",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
enforcement_disabled = json.dumps({
    "action": "admin_single_sign_on_update",
    "description": "{\"enforcement_status\": \"disabled\"}",
    "isotimestamp": "2021-10-12 21:29:22",
    "timestamp": "2021-10-12 21:29:22",
    "username": "Homer Simpson"
})
endpoint_is_not_in_management_system = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {},
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "endpoint_is_not_in_management_system",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
admin_lockout__valid_json = json.dumps({
    "action": "admin_lockout",
    "description": "{\"message\": \"Admin temporarily locked out due to too many passcode attempts.\"}",
    "isotimestamp": "2022-12-14 21:02:03",
    "timestamp": "2022-12-14 21:02:03",
    "username": "Homer Simpson"
})
phones_update = json.dumps({
    "action": "user_update",
    "description": "{\"phones\": \"\"}",
    "isotimestamp": "2021-07-02 19:06:40",
    "object": "homer.simpson@simpsons.com",
    "timestamp": "2021-07-02 19:06:40",
    "username": "Homer Simpson"
})
login_event = json.dumps({
    "action": "admin_login",
    "description": "{\"ip_address\": \"1.2.3.4\", \"device\": \"123-456-789\", \"factor\": \"sms\", \"saml_idp\": \"OneLogin\", \"primary_auth_method\": \"Single Sign-On\"}",
    "isotimestamp": "2021-06-30 19:45:37",
    "timestamp": "2021-06-30 19:45:37",
    "username": "Homer Simpson"
})
could_not_determine_if_endpoint_was_trusted = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {},
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "could_not_determine_if_endpoint_was_trusted",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
anomalous_push_occurred = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {
        "key": "D12345",
        "name": "Slack"
    },
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "anomalous_push",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
bypass_enabled = json.dumps({
    "action": "user_update",
    "description": "{\"status\": \"Bypass\"}",
    "isotimestamp": "2021-10-05 22:45:33",
    "object": "bart.simpson@simpsons.com",
    "timestamp": "2021-10-05 22:45:33",
    "username": "Homer Simpson"
})
other_event = json.dumps({
    "action": "admin_login",
    "description": "{\"ip_address\": \"1.2.3.4\", \"device\": \"123-456-123\", \"factor\": \"sms\", \"saml_idp\": \"OneLogin\", \"primary_auth_method\": \"Single Sign-On\"}",
    "isotimestamp": "2021-07-02 18:31:25",
    "timestamp": "2021-07-02 18:31:25",
    "username": "Homer Simpson"
})
bypass_code_used = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {
        "key": "D12345",
        "name": "Slack"
    },
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "bypass_user",
    "result": "success",
    "user": {
        "name": "example@example.io"
    }
})
endpoint_failed_google_verification = json.dumps({
    "access_device": {
        "ip": "12.12.112.25",
        "os": "Mac OS X"
    },
    "auth_device": {
        "ip": "12.12.12.12"
    },
    "application": {},
    "event_type": "authentication",
    "factor": "duo_push",
    "reason": "endpoint_failed_google_verification",
    "result": "denied",
    "user": {
        "name": "example@example.io"
    }
})
