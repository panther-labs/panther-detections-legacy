import json

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

workspace_admin_creates_default_routing_rule = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '110555555555555555555'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 00:50:03.493000000', 'uniqueQualifier': '-6333333333333333333'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CREATE_GMAIL_SETTING', 'parameters': {'SETTING_NAME': 'MESSAGE_SECURITY_RULE', 'USER_DEFINED_SETTING_NAME': '44444'}, 'type': 'EMAIL_SETTINGS'})
normal_login_event = json.dumps({'id': {'applicationName': 'login'}, 'type': 'login'})
workspace_admin_enabled_password_reuse = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:18:47.973000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'standard', 'APPLICATION_NAME': 'Security', 'NEW_VALUE': 'true', 'OLD_VALUE': 'false', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'Password Management - Enable password reuse'}, 'type': 'APPLICATION_SETTINGS'})
account_warning_not_for_password_leaked = json.dumps({'id': {'applicationName': 'login'}, 'type': 'account_warning', 'name': 'account_disabled_spamming', 'parameters': {'affected_email_address': 'homer.simpson@example.com'}})
change_email_setting = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-10 23:38:45.125000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_EMAIL_SETTING', 'parameters': {'NEW_VALUE': '3', 'OLD_VALUE': '2', 'ORG_UNIT_NAME': 'EXAMPLE IO', 'SETTING_NAME': 'ENABLE_G_SUITE_MARKETPLACE'}, 'type': 'EMAIL_SETTINGS'})
non_default_calendar_sharing_outside_domain_event = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '111111111111111111111'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-12 22:21:40.106000000', 'uniqueQualifier': '1000000000000000000'}, 'kind': 'admin#reports#activity', 'name': 'CUSTOMER_TAKEOUT_SUCCEEDED', 'parameters': {'OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID': '00mmmmmmmmmmmmm'}, 'type': 'CUSTOMER_TAKEOUT'})
other_admin_action = json.dumps({'id': {'applicationName': 'admin'}, 'type': 'DELEGATED_ADMIN_SETTINGS', 'name': 'RENAME_ROLE', 'parameters': {'ROLE_NAME': 'Vault Admins', 'USER_EMAIL': 'homer.simpson@example.com'}})
workspace_admin_deletes_default_routing_rule = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '110555555555555555555'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 00:50:41.760000000', 'uniqueQualifier': '-5015136739334825037'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'DELETE_GMAIL_SETTING', 'parameters': {'SETTING_NAME': 'MESSAGE_SECURITY_RULE', 'USER_DEFINED_SETTING_NAME': '44444'}, 'type': 'EMAIL_SETTINGS'})
suspicious_activity_shows_compromised = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'DEVICE_COMPROMISED_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'DEVICE_COMPROMISED_STATE': 'COMPROMISED'}})
admin_set_default_calendar_sharing_outside_domain_setting_to_read_write_access = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:06:26.303000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_CALENDAR_SETTING', 'parameters': {'DOMAIN_NAME': 'example.io', 'NEW_VALUE': 'READ_WRITE_ACCESS', 'OLD_VALUE': 'READ_ONLY_ACCESS', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'SHARING_OUTSIDE_DOMAIN'}, 'type': 'CALENDAR_SETTINGS'})
workspace_admin_add_trusted_domain = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '110506209185950390992'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-10 23:59:24.470000000', 'uniqueQualifier': '-334478670839567761'}, 'kind': 'admin#reports#activity', 'name': 'ADD_TRUSTED_DOMAINS', 'parameters': {'DOMAIN_NAME': 'evilexample.com'}, 'type': 'DOMAIN_SETTINGS'})
normal_login_event = json.dumps({'id': {'applicationName': 'login'}, 'kind': 'admin#reports#activity', 'type': 'account_warning', 'name': 'login_success', 'parameters': {'affected_email_address': 'bobert@ext.runpanther.io'}})
government_backed_attack_warning = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'homer.simpson@example.com'}, 'type': 'login', 'name': 'gov_attack_warning', 'parameters': {'is_suspicious': None, 'login_challenge_method': ['none']}})
suspicious_activity_shows_not_compromised = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'DEVICE_COMPROMISED_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'DEVICE_COMPROMISED_STATE': 'NOT_COMPROMISED'}})
non_forwarding_event = json.dumps({'id': {'applicationName': 'user_accounts', 'customerId': 'D12345'}, 'actor': {'email': 'homer.simpson@.springfield.io'}, 'type': '2sv_change', 'name': '2sv_enroll'})
multiple_failed_login_attempts_with_int_type = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'FAILED_PASSWORD_ATTEMPTS_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'FAILED_PASSWD_ATTEMPTS': 100}})
workspace_admin_data_export_created = json.dumps({'actor': {'callerType': 'USER', 'email': 'admin@example.io', 'profileId': '11011111111111111111111'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-10 22:21:40.079000000', 'uniqueQualifier': '-2833899999999999999'}, 'kind': 'admin#reports#activity', 'name': 'CUSTOMER_TAKEOUT_CREATED', 'parameters': {'OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID': '00mmmmmmmmmmmmm'}, 'type': 'CUSTOMER_TAKEOUT'})
user_banned_from_group = json.dumps({'id': {'applicationName': 'groups_enterprise'}, 'actor': {'email': 'homer.simpson@example.com'}, 'type': 'moderator_action', 'name': 'ban_user_with_moderation'})
account_warning_for_suspended_user = json.dumps({'id': {'applicationName': 'login'}, 'kind': 'admin#reports#activity', 'type': 'account_warning', 'name': 'account_disabled_spamming', 'parameters': {'affected_email_address': 'bobert@ext.runpanther.io'}})
suspicious_activity = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'SUSPICIOUS_ACTIVITY_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io'}})
parameters_json_key_set_to_null_value = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '111111111111111111111'}, 'id': {'applicationName': 'user_accounts', 'customerId': 'C00000000', 'time': '2022-12-29 22:42:44.467000000', 'uniqueQualifier': '517500000000000000'}, 'parameters': None, 'ipAddress': '2600:2600:2600:2600:2600:2600:2600:2600', 'kind': 'admin#reports#activity', 'name': 'recovery_email_edit', 'type': 'recovery_info_change'})
resource_accessed_by_google = json.dumps({'id': {'applicationName': 'access_transparency'}, 'type': 'GSUITE_RESOURCE'})
high_severity_rule_with_rule_name = json.dumps({'id': {'applicationName': 'rules'}, 'actor': {'email': 'some.user@somedomain.com'}, 'parameters': {'severity': 'HIGH', 'rule_name': 'CEO Impersonation', 'triggered_actions': [{'action_type': 'MAIL_MARK_AS_PHISHING'}]}})
advanced_protection_disabled = json.dumps({'id': {'applicationName': 'user_accounts'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.com'}, 'type': 'titanium_change', 'name': 'titanium_unenroll'})
saml_login_event = json.dumps({'actor': {'email': 'some.user@somedomain.com'}, 'id': {'applicationName': 'saml', 'time': '2022-05-26 15:26:09.421000000'}, 'ipAddress': '10.10.10.10', 'kind': 'admin#reports#activity', 'name': 'login_success', 'parameters': {'application_name': 'Some SAML Application', 'initiated_by': 'sp', 'orgunit_path': '/SomeOrgUnit', 'saml_status_code': 'SUCCESS_URI'}, 'type': 'login'})
user_publically_shared_a_calendar = json.dumps({'actor': {'email': 'user@example.io', 'profileId': '110111111111111111111'}, 'id': {'applicationName': 'calendar', 'customerId': 'D12345', 'time': '2022-12-10 22:33:31.852000000', 'uniqueQualifier': '-2888888888888888888'}, 'ipAddress': '1.2.3.4', 'kind': 'admin#reports#activity', 'name': 'change_calendar_acls', 'ownerDomain': 'example.io', 'parameters': {'access_level': 'freebusy', 'api_kind': 'web', 'calendar_id': 'user@example.io', 'grantee_email': '__public_principal__@public.calendar.google.com', 'user_agent': 'Mozilla/5.0'}, 'type': 'calendar_change'})
allow_security_codes = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:35:29.906000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CREATE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'standard', 'APPLICATION_NAME': 'Security', 'NEW_VALUE': 'ALLOWED_WITH_REMOTE_ACCESS', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'Advanced Protection Program Settings - Allow security codes'}, 'type': 'APPLICATION_SETTINGS'})
account_warning_for_suspicious_login = json.dumps({'id': {'applicationName': 'login'}, 'kind': 'admin#reports#activity', 'type': 'account_warning', 'name': 'suspicious_login', 'parameters': {'affected_email_address': 'bobert@ext.runpanther.io'}})
account_warning_not_for_suspicious_login = json.dumps({'id': {'applicationName': 'login'}, 'kind': 'admin#reports#activity', 'type': 'account_warning', 'name': 'account_disabled_spamming', 'parameters': {'affected_email_address': 'bobert@ext.runpanther.io'}})
workspace_admin_disables_security_sandbox = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 03:31:41.212000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'enterprise', 'APPLICATION_NAME': 'Gmail', 'NEW_VALUE': 'false', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'AttachmentDeepScanningSettingsProto deep_scanning_enabled'}, 'type': 'APPLICATION_SETTINGS'})
android_calculator = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-10 22:55:38.478000000', 'uniqueQualifier': '12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'ADD_MOBILE_APPLICATION_TO_WHITELIST', 'parameters': {'DEVICE_TYPE': 'Android', 'DISTRIBUTION_ENTITY_NAME': '/', 'DISTRIBUTION_ENTITY_TYPE': 'ORG_UNIT', 'MOBILE_APP_PACKAGE_ID': 'com.google.android.calculator'}, 'type': 'MOBILE_SETTINGS'})
enable_user_enrollment = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:35:29.906000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CREATE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'standard', 'APPLICATION_NAME': 'Security', 'NEW_VALUE': 'true', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'Advanced Protection Program Settings - Enable user enrollment'}, 'type': 'APPLICATION_SETTINGS'})
normal_mobile_event = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'DEVICE_REGISTER_UNREGISTER_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io'}})
normal_login_event = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'homer.simpson@example.com'}, 'type': 'login', 'name': 'login_success', 'parameters': {'is_suspicious': None, 'login_challenge_method': ['none']}})
document_transferred_to_external_user = json.dumps({'id': {'applicationName': 'admin'}, 'name': 'TRANSFER_DOCUMENT_OWNERSHIP', 'parameters': {'NEW_VALUE': 'monty.burns@badguy.com'}})
login_with_unapproved_type = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'some.user@somedomain.com'}, 'type': 'login', 'name': 'login_success', 'parameters': {'login_type': 'turbo-snail'}})
privileges_assigned = json.dumps({'id': {'applicationName': 'admin'}, 'type': 'DELEGATED_ADMIN_SETTINGS', 'name': 'ASSIGN_ROLE', 'parameters': {'ROLE_NAME': 'Vault Admins', 'USER_EMAIL': 'homer.simpson@example.com'}})
ownership_transferred_within_organization = json.dumps({'id': {'applicationName': 'admin'}, 'name': 'TRANSFER_DOCUMENT_OWNERSHIP', 'parameters': {'NEW_VALUE': 'homer.simpson@example.com'}})
multiple_failed_login_attempts_with_string_type = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'FAILED_PASSWORD_ATTEMPTS_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'FAILED_PASSWD_ATTEMPTS': '100'}})
two_step_verification_disabled = json.dumps({'id': {'applicationName': 'user_accounts'}, 'actor': {'callerType': 'USER', 'email': 'some.user@somedomain.com'}, 'kind': 'admin#reports#activity', 'type': '2sv_change', 'name': '2sv_disable'})
workspace_admin_disables_enhanced_pre_delivery_scanning = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 03:42:54.859000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'business_plus_2021', 'APPLICATION_NAME': 'Gmail', 'NEW_VALUE': 'true', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email'}, 'type': 'APPLICATION_SETTINGS'})
workspace_admin_disabled_strong_password_enforcement = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '110111111111111111111'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:33:56.306000000', 'uniqueQualifier': '-6444444444444444444'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'enterprise', 'APPLICATION_NAME': 'Security', 'NEW_VALUE': 'off', 'OLD_VALUE': 'on', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'Password Management - Enforce strong password'}, 'type': 'APPLICATION_SETTINGS'})
docusign_for_google = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-10 23:05:39.508000000', 'uniqueQualifier': '-12345'}, 'kind': 'admin#reports#activity', 'name': 'ADD_APPLICATION', 'parameters': {'APP_ID': '469176070494', 'APPLICATION_ENABLED': 'true', 'APPLICATION_NAME': 'DocuSign eSignature for Google'}, 'type': 'DOMAIN_SETTINGS'})
medium_severity_rule = json.dumps({'id': {'applicationName': 'rules'}, 'actor': {'email': 'some.user@somedomain.com'}, 'parameters': {'data_source': 'DRIVE', 'severity': 'MEDIUM', 'triggered_actions': [{'action_type': 'DRIVE_UNFLAG_DOCUMENT'}]}})
failed_login = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'some.user@somedomain.com'}, 'type': 'login', 'name': 'login_failure'})
delete_role = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '123456'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 02:57:48.693000000', 'uniqueQualifier': '-12456'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'DELETE_ROLE', 'parameters': {'ROLE_ID': '567890', 'ROLE_NAME': 'CustomAdminRoleName'}, 'type': 'DELEGATED_ADMIN_SETTINGS'})
admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:06:26.303000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_CALENDAR_SETTING', 'parameters': {'DOMAIN_NAME': 'example.io', 'NEW_VALUE': 'READ_ONLY_ACCESS', 'OLD_VALUE': 'DEFAULT', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'SHARING_OUTSIDE_DOMAIN'}, 'type': 'CALENDAR_SETTINGS'})
listobject_type = json.dumps({'actor': {'email': 'user@example.io', 'profileId': '118111111111111111111'}, 'id': {'applicationName': 'drive', 'customerId': 'D12345', 'time': '2022-12-20 17:27:47.080000000', 'uniqueQualifier': '-7312729053723258069'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'rename', 'parameters': {'actor_is_collaborator_account': None, 'billable': True, 'doc_id': '1GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG', 'doc_title': 'Document Title- Found Here', 'doc_type': 'presentation', 'is_encrypted': None, 'new_value': ['Document Title- Found Here'], 'old_value': ['Document Title- Old'], 'owner': 'user@example.io', 'owner_is_shared_drive': None, 'owner_is_team_drive': None, 'primary_event': True, 'visibility': 'private'}, 'type': 'access'})
change_email_setting_default = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D1234', 'time': '2022-12-10 23:33:04.667000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_EMAIL_SETTING', 'parameters': {'NEW_VALUE': '1', 'OLD_VALUE': 'DEFAULT', 'ORG_UNIT_NAME': 'EXAMPLE IO', 'SETTING_NAME': 'ENABLE_G_SUITE_MARKETPLACE'}, 'type': 'EMAIL_SETTINGS'})
other_login_event = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'some.user@somedomain.com'}, 'type': 'login', 'name': 'login_verification'})
workspace_admin_remove_trusted_domain = json.dumps({'actor': {'callerType': 'USER', 'email': 'user@example.io', 'profileId': '110506209185950390992'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 00:01:34.643000000', 'uniqueQualifier': '-2972206985263071668'}, 'kind': 'admin#reports#activity', 'name': 'REMOVE_TRUSTED_DOMAINS', 'p_source_label': 'Staging', 'parameters': {'DOMAIN_NAME': 'evilexample.com'}, 'type': 'DOMAIN_SETTINGS'})
microsoft_apps_for_google = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-10 23:05:39.508000000', 'uniqueQualifier': '-12345'}, 'kind': 'admin#reports#activity', 'name': 'ADD_APPLICATION', 'parameters': {'APP_ID': '469176070494', 'APPLICATION_ENABLED': 'true', 'APPLICATION_NAME': 'Microsoft Applications for Google'}, 'type': 'DOMAIN_SETTINGS'})
user_added = json.dumps({'id': {'applicationName': 'groups_enterprise'}, 'actor': {'email': 'homer.simpson@example.com'}, 'type': 'moderator_action', 'name': 'add_member'})
new_custom_role_created = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '123456'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 02:57:48.693000000', 'uniqueQualifier': '-12456'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CREATE_ROLE', 'parameters': {'ROLE_ID': '567890', 'ROLE_NAME': 'CustomAdminRoleName'}, 'type': 'DELEGATED_ADMIN_SETTINGS'})
enable_user_enrollement = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:35:29.906000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CREATE_APPLICATION_SETTING', 'parameters': {'APPLICATION_EDITION': 'standard', 'APPLICATION_NAME': 'Security', 'NEW_VALUE': 'true', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'Advanced Protection Program Settings - Enable user enrollment'}, 'type': 'APPLICATION_SETTINGS'})
admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access = json.dumps({'actor': {'callerType': 'USER', 'email': 'example@example.io', 'profileId': '12345'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-11 01:06:26.303000000', 'uniqueQualifier': '-12345'}, 'ipAddress': '12.12.12.12', 'kind': 'admin#reports#activity', 'name': 'CHANGE_CALENDAR_SETTING', 'parameters': {'DOMAIN_NAME': 'example.io', 'NEW_VALUE': 'MANAGE_ACCESS', 'OLD_VALUE': 'READ_WRITE_ACCESS', 'ORG_UNIT_NAME': 'Example IO', 'SETTING_NAME': 'SHARING_OUTSIDE_DOMAIN'}, 'type': 'CALENDAR_SETTINGS'})
non_triggered_rule = json.dumps({'id': {'applicationName': 'rules'}, 'actor': {'email': 'some.user@somedomain.com'}, 'parameters': {'severity': 'HIGH', 'triggered_actions': None}})
non_login_event = json.dumps({'id': {'applicationName': 'logout'}, 'actor': {'email': 'some.user@somedomain.com'}, 'type': 'login', 'name': 'login_success', 'parameters': {'login_type': 'saml'}})
normal_mobile_event = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'DEVICE_SYNC_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io'}})
account_warning_for_password_leaked = json.dumps({'id': {'applicationName': 'login'}, 'type': 'account_warning', 'name': 'account_disabled_password_leak', 'parameters': {'affected_email_address': 'homer.simpson@example.com'}})
advanced_protection_enabled = json.dumps({'id': {'applicationName': 'user_accounts'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.com'}, 'type': 'titanium_change', 'name': 'titanium_enroll'})
workspace_admin_data_export_succeeded = json.dumps({'actor': {'callerType': 'USER', 'email': 'admin@example.io', 'profileId': '11011111111111111111111'}, 'id': {'applicationName': 'admin', 'customerId': 'D12345', 'time': '2022-12-12 22:21:40.106000000', 'uniqueQualifier': '3005999999999999999'}, 'kind': 'admin#reports#activity', 'name': 'CUSTOMER_TAKEOUT_SUCCEEDED', 'parameters': {'OBFUSCATED_CUSTOMER_TAKEOUT_REQUEST_ID': '00mmmmmmmmmmmmm'}, 'type': 'CUSTOMER_TAKEOUT'})
normal_login_event = json.dumps({'id': {'applicationName': 'login'}, 'type': 'login', 'name': 'logout', 'parameters': {'login_type': 'saml'}})
small_number_of_failed_logins = json.dumps({'id': {'applicationName': 'mobile'}, 'actor': {'callerType': 'USER', 'email': 'homer.simpson@example.io'}, 'type': 'device_updates', 'name': 'FAILED_PASSWORD_ATTEMPTS_EVENT', 'parameters': {'USER_EMAIL': 'homer.simpson@example.io', 'FAILED_PASSWD_ATTEMPTS': 2}})
low_severity_rule = json.dumps({'id': {'applicationName': 'rules'}, 'actor': {'email': 'some.user@somedomain.com'}, 'parameters': {'severity': 'LOW', 'triggered_actions': [{'action_type': 'DRIVE_UNFLAG_DOCUMENT'}]}})
high_severity_rule = json.dumps({'id': {'applicationName': 'rules'}, 'actor': {'email': 'some.user@somedomain.com'}, 'parameters': {'data_source': 'DRIVE', 'severity': 'HIGH', 'triggered_actions': [{'action_type': 'DRIVE_UNFLAG_DOCUMENT'}]}})
account_warning_not_for_user_suspended = json.dumps({'id': {'applicationName': 'login'}, 'kind': 'admin#reports#activity', 'type': 'account_warning', 'name': 'suspicious_login ', 'parameters': {'affected_email_address': 'bobert@ext.runpanther.io'}})
successful_login = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'some.user@somedomain.com'}, 'type': 'login', 'name': 'login_success'})
forwarding_to_external_address = json.dumps({'id': {'applicationName': 'user_accounts', 'customerId': 'D12345'}, 'actor': {'email': 'homer.simpson@.springfield.io'}, 'type': 'email_forwarding_change', 'name': 'email_forwarding_out_of_domain', 'parameters': {'email_forwarding_destination_address': 'HSimpson@gmail.com'}})
login_with_approved_type = json.dumps({'id': {'applicationName': 'login'}, 'actor': {'email': 'some.user@somedomain.com'}, 'type': 'login', 'name': 'login_success', 'parameters': {'login_type': 'saml'}})
forwarding_to_external_address___allowed_domain = json.dumps({'id': {'applicationName': 'user_accounts', 'customerId': 'D12345'}, 'actor': {'email': 'homer.simpson@.springfield.io'}, 'type': 'email_forwarding_change', 'name': 'email_forwarding_out_of_domain', 'parameters': {'email_forwarding_destination_address': 'HSimpson@example.com'}})
two_step_verification_enabled = json.dumps({'id': {'applicationName': 'user_accounts'}, 'actor': {'callerType': 'USER', 'email': 'some.user@somedomain.com'}, 'kind': 'admin#reports#activity', 'type': '2sv_change', 'name': '2sv_enroll'})
