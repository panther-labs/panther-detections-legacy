import json

admin_impersonated_user_successfully = json.dumps(
    {
    "attributes": {
        "action": "user_logged_in_as_user",
        "actor": {
        "email": "example.admin@example.com",
        "id": "1234567890abcdefghijklmn",
        "name": "Example Admin"
        },
        "container": [
        {
            "attributes": {
            "siteHostName": "https://example.atlassian.net",
            "siteName": "example"
            },
            "id": "12345678-abcd-9012-efgh-1234567890abcd",
            "links": {
            "alt": "https://example.atlassian.net"
            },
            "type": "sites"
        }
        ],
        "context": [
        {
            "attributes": {
            "accountType": "atlassian",
            "email": "example.user@example.io",
            "name": "example.user@example.io"
            },
            "type": "users"
        }
        ],
        "time": "2022-12-15T00:35:15.890Z"
    },
    "id": "2508d209-3336-4763-89a0-aceaf1322fcf", #event ID
            "message": {
        "content": "Logged in as example.user@example.io",
        "format": "simple"
    },
    }
)

user_logged_in_as_user_not_in_log = json.dumps(
    {
    "attributes": {
        "action": "user_login",
        "actor": {
        "email": "example.admin@example.com",
        "id": "1234567890abcdefghijklmn",
        "name": "Example Admin"
        },
        "container": [
        {
            "attributes": {
            "siteHostName": "https://example.atlassian.net",
            "siteName": "example"
            },
            "id": "12345678-abcd-9012-efgh-1234567890abcd",
            "links": {
            "alt": "https://example.atlassian.net"
            },
            "type": "sites"
        }
        ],
        "context": [
        {
            "attributes": {
            "accountType": "atlassian",
            "email": "example.user@example.io",
            "name": "example.user@example.io"
            },
            "type": "users"
        }
        ],
        "time": "2022-12-15T00:35:15.890Z"
    },
    "id": "2508d209-3336-4763-89a0-aceaf1322fcf", #event ID
    "message": {
        "content": "Logged in as example.user@example.io",
        "format": "simple"
    },
    }
)