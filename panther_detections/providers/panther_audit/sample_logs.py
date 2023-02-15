import json
saml_modified_saml_config_modified = json.dumps({
    "actionName": "UPDATE_SAML_SETTINGS",
    "actionParams": {},
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "111111"
        },
        "id": "111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit"
})
saml_modified_saml_config_viewed = json.dumps({
    "actionName": "GET_SAML_SETTINGS",
    "actionParams": {},
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "111111"
        },
        "id": "111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit"
})
user_modified_admin_role_created = json.dumps({
    "actionName": "CREATE_USER_ROLE",
    "actionParams": {
        "input": {
            "logTypeAccessKind": "DENY_ALL",
            "name": "New Admins",
            "permissions": [
                "GeneralSettingsModify",
                "GeneralSettingsRead",
                "SummaryRead"
            ]
        }
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "1111111"
        },
        "id": "11111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit",
    "pantherVersion": "1.2.3",
    "sourceIP": "1.2.3.4",
    "timestamp": "2022-04-27 20:47:09.425"
})
user_modified_users_email_was_changed = json.dumps({
    "XForwardedFor": [
        "1.2.3.4",
        "5.6.7.8"
    ],
    "actionDescription": "Updates the information for a user",
    "actionName": "UPDATE_USER",
    "actionParams": {
        "dynamic": {
            "input": {
                "email": "user-email+anyplus@springfield.gov",
                "familyName": "Email",
                "givenName": "User",
                "id": "75757575-7575-7575-7575-757575757575",
                "role": {
                    "kind": "ID",
                    "value": "(redacted)"
                }
            }
        },
        "static": {}
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "admin.email@springfield.gov",
            "emailVerified": False,
            "roleId": "89898989-8989-8989-8989-898989898989",
            "roleName": "Admin"
        },
        "id": "PantherSSO_admin.email@springfield.gov",
        "name": "admin.email@springfield.gov",
        "type": "USER"
    },
    "p_any_ip_addresses": [
        "5.6.7.8",
        "1.2.3.4"
    ],
    "p_any_trace_ids": [
        "PantherSSO_admin.email@springfield.gov"
    ],
    "p_any_usernames": [
        "admin.email@springfield.gov"
    ],
    "p_event_time": "2022-11-08 19:23:04.841",
    "p_log_type": "Panther.Audit",
    "p_parse_time": "2022-11-08 19:23:47.278",
    "p_row_id": "12341234123412341234123412341234",
    "p_source_id": "34343434-3434-3434-3434-343434343434",
    "p_source_label": "panther-audit-logs-region-name",
    "pantherVersion": "1.2.3",
    "sourceIP": "1.2.3.4",
    "timestamp": "2022-11-08 19:23:04.841",
    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
})
user_modified_users_role_was_changed = json.dumps({
    "XForwardedFor": [
        "5.6.7.8",
        "1.2.3.4"
    ],
    "actionDescription": "Updates the information for a user",
    "actionName": "UPDATE_USER",
    "actionParams": {
        "dynamic": {
            "input": {
                "email": "user.email@springfield.gov",
                "familyName": "Email",
                "givenName": "User",
                "id": "PantherSSO_user.email@springfield.gov",
                "role": {
                    "kind": "ID",
                    "value": "(redacted)"
                }
            }
        },
        "static": {}
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "admin.email@springfield.gov",
            "emailVerified": False,
            "roleId": "12341234-1234-1234-1234-123412341234",
            "roleName": "Admin"
        },
        "id": "PantherSSO_admin.email@springfield.gov",
        "name": "admin.email@springfield.gov",
        "type": "USER"
    },
    "p_any_ip_addresses": [
        "5.6.7.8",
        "1.2.3.4"
    ],
    "p_any_trace_ids": [
        "PantherSSO_admin.email@springfield.gov"
    ],
    "p_any_usernames": [
        "admin.email@springfield.gov"
    ],
    "p_event_time": "2022-11-09 23:10:35.504",
    "p_log_type": "Panther.Audit",
    "p_parse_time": "2022-11-09 23:11:47.112",
    "p_row_id": "56785678567856785678567856785678",
    "p_source_id": "34563456-3456-3456-3456-345634563456",
    "p_source_label": "panther-audit-logs-region-name",
    "pantherVersion": "1.2.3",
    "sourceIP": "5.6.7.8",
    "timestamp": "2022-11-09 23:10:35.504",
    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
})
detection_deleted_delete_1_detection = json.dumps({
    "actionName": "DELETE_DETECTION",
    "actionParams": {
        "input": {
            "detections": [
                {
                    "id": "GitHub.Team.Modified"
                }
            ]
        }
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "11111111"
        },
        "id": "1111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit",
    "sourceIP": "1.2.3.4",
    "timestamp": "2022-04-28 15:30:22.42"
})
detection_deleted_delete_many_detections = json.dumps({
    "actionName": "DELETE_DETECTION",
    "actionParams": {
        "input": {
            "detections": [
                {
                    "id": "Github.Repo.Created"
                },
                {
                    "id": "Okta.Global.MFA.Disabled"
                },
                {
                    "id": "Okta.AdminRoleAssigned"
                },
                {
                    "id": "Okta.BruteForceLogins"
                }
            ]
        }
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "111111"
        },
        "id": "1111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit",
    "sourceIP": "1.2.3.4.",
    "timestamp": "2022-04-28 15:34:43.067"
})
detection_deleted_non_delete_event = json.dumps({
    "actionName": "GET_GENERAL_SETTINGS",
    "actionParams": {},
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "111111"
        },
        "id": "111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit"
})
sensitive_role_created_admin_role_created = json.dumps({
    "actionName": "CREATE_USER_ROLE",
    "actionParams": {
        "input": {
            "logTypeAccessKind": "DENY_ALL",
            "name": "New Admins",
            "permissions": [
                "GeneralSettingsModify",
                "GeneralSettingsRead",
                "SummaryRead"
            ]
        }
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "1111111"
        },
        "id": "11111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit",
    "pantherVersion": "1.2.3",
    "sourceIP": "1.2.3.4",
    "timestamp": "2022-04-27 20:47:09.425"
})
sensitive_role_created_non_admin_role_created = json.dumps({
    "actionName": "CREATE_USER_ROLE",
    "actionParams": {
        "input": {
            "logTypeAccessKind": "DENY_ALL",
            "name": "New Admins",
            "permissions": [
                "SummaryRead"
            ]
        }
    },
    "actionResult": "SUCCEEDED",
    "actor": {
        "attributes": {
            "email": "homer@springfield.gov",
            "emailVerified": True,
            "roleId": "1111111"
        },
        "id": "11111111",
        "name": "Homer Simpson",
        "type": "USER"
    },
    "errors": None,
    "p_log_type": "Panther.Audit",
    "pantherVersion": "1.2.3",
    "sourceIP": "1.2.3.4",
    "timestamp": "2022-04-27 20:47:09.425"
})
sensitive_role_created_nonetype_error = json.dumps({
    "XForwardedFor": [
        "1.2.3.4",
        "5.6.7.8"
    ],
    "actionDescription": "Adds a new User role to Panther",
    "actionName": "CREATE_USER_ROLE",
    "actionParams": {
        "dynamic": {
            "input": {
                "logTypeAccess": [
                    "Okta.SystemLog"
                ],
                "logTypeAccessKind": "ALLOW",
                "name": "ITE Role",
                "permissions": [
                    "AlertRead",
                    "DataAnalyticsRead"
                ]
            }
        },
        "static": {}
    },
    "actionResult": "FAILED",
    "actor": {
        "attributes": {
            "email": "random@noreply.com",
            "emailVerified": False,
            "roleId": "2a7bfe22-666d-4f71-99d2-c16b8666eca1",
            "roleName": "Admin"
        },
        "id": "PantherSSO_random@noreply.com",
        "name": "random@noreply.com",
        "type": "USER"
    },
    "errors": [
        {
            "message": "You cannot save a role that has both log type restrictions and alerts/detections permissions at this time."
        }
    ],
    "p_alert_creation_time": "2023-02-09 21:47:09.745566000",
    "p_alert_id": "7eb5ca596b2153f95885cb2440e12345",
    "p_alert_severity": "HIGH",
    "p_alert_update_time": "2023-02-09 21:47:09.745566000",
    "p_any_ip_addresses": [
        "1.2.3.4",
        "5.6.7.8"
    ],
    "p_any_trace_ids": [
        "PantherSSO_random@noreply.com"
    ],
    "p_any_usernames": [
        "random@noreply.com"
    ],
    "p_enrichment": {
        "ipinfo_asn": {
            "sourceIP": {
                "asn": "AS396982",
                "domain": "google.com",
                "name": "Google LLC",
                "route": "208.127.224.0/21",
                "type": "hosting"
            }
        },
        "ipinfo_location": {
            "sourceIP": {
                "city": "Ashburn",
                "country": "US",
                "lat": "39.04372",
                "lng": "-77.48749",
                "postal_code": "20147",
                "region": "Virginia",
                "region_code": "VA",
                "timezone": "America/New_York"
            }
        }
    },
    "p_event_time": "2023-02-09 21:45:59.352910070",
    "p_log_type": "Panther.Audit",
    "p_parse_time": "2023-02-09 21:46:53.858602089",
    "p_row_id": "b29dff36ad73cb77a5d7a3a816c39c2a",
    "p_rule_error": "'NoneType' object is not iterable: Panther.Sensitive.Role.py, line 20, in rule    role_permissions = set(deep_get(event, \"actionParams\", \"input\", \"permissions\"))",
    "p_rule_id": "Panther.Sensitive.Role",
    "p_rule_reports": {
        "MITRE ATT&CK": [
            "TA0003:T1098"
        ]
    },
    "p_rule_severity": "HIGH",
    "p_rule_tags": [
        "DataModel",
        "Persistence:Account Manipulation"
    ],
    "p_schema_version": 0,
    "p_source_id": "9a116557-0a1c-4a21-8565-1135dfe5e82b",
    "p_source_label": "panther-audit-logs-us-east-1",
    "pantherVersion": "1.53.7",
    "sourceIP": "1.2.3.4",
    "timestamp": "2023-02-09 21:45:59.352910070",
    "userAgent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36"
})
