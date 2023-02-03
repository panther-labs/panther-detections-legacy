import json

expected_client = json.dumps(
    {
        "uuid": "1234",
        "session_uuid": "12345",
        "timestamp": "2021-12-15 18:02:23",
        "category": "success",
        "type": "credentials_ok",
        "country": "US",
        "target_user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "1234"},
        "client": {
            "app_name": "1Password for Mac",
            "app_version": "70902005",
            "ip_address": "1.1.1.1",
            "os_name": "MacOSX",
            "os_version": "11.6.1",
            "platform_name": "US - C02FR0H8MD6P",
            "platform_version": "MacBookPro16,1",
        },
        "p_log_type": "OnePassword.SignInAttempt",
    }
)


bad_client = json.dumps(
    {
        "uuid": "1234",
        "session_uuid": "12345",
        "timestamp": "2021-12-15 18:02:23",
        "category": "success",
        "type": "credentials_ok",
        "country": "US",
        "target_user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "1234"},
        "client": {
            "app_name": "Bartco 1Password Manager",
            "app_version": "70902005",
            "ip_address": "1.1.1.1",
            "os_name": "MacOSX",
            "os_version": "11.6.1",
            "platform_name": "US - C02FR0H8MD6P",
            "platform_version": "MacBookPro16,1",
        },
        "p_log_type": "OnePassword.SignInAttempt",
    }
)


sensitive_item_accessed = json.dumps(
    {
        "uuid": "ecd1d435c26440dc930ddfbbef201a11",
        "timestamp": "2022-02-23 20:27:17.071",
        "used_version": 2,
        "vault_uuid": "111111",
        "item_uuid": "ecd1d435c26440dc930ddfbbef201a11",
        "user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "2222222"},
        "client": {
            "app_name": "1Password Browser Extension",
            "app_version": "20195",
            "ip_address": "1.1.1.1.1",
            "os_name": "MacOSX",
            "os_version": "10.15.7",
            "platform_name": "Chrome",
            "platform_version": "4.0.4.102",
        },
        "p_log_type": "OnePassword.ItemUsage",
    }
)


regular_item_usage = json.dumps(
    {
        "uuid": "11111",
        "timestamp": "2022-02-23 20:27:17.071",
        "used_version": 2,
        "vault_uuid": "111111",
        "item_uuid": "1111111",
        "user": {"email": "homer@springfield.gov", "name": "Homer Simpson", "uuid": "2222222"},
        "client": {
            "app_name": "1Password Browser Extension",
            "app_version": "20195",
            "ip_address": "1.1.1.1.1",
            "os_name": "MacOSX",
            "os_version": "10.15.7",
            "platform_name": "Chrome",
            "platform_version": "4.0.4.102",
        },
        "p_log_type": "OnePassword.ItemUsage",
    }
)
