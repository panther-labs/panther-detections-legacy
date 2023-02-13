import json

public_repository_created_public_repo_created = json.dumps(
    {
        "_document_id": "abCD",
        "action": "repo.create",
        "actor": "example-actor",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-11 22:40:20.268",
        "created_at": "2022-12-11 22:40:20.268",
        "org": "example-io",
        "repo": "example-io/oops",
        "visibility": "public",
    }
)

public_repository_created_private_repo_created = json.dumps(
    {
        "_document_id": "abCD",
        "action": "repo.create",
        "actor": "example-actor",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-11 22:40:20.268",
        "created_at": "2022-12-11 22:40:20.268",
        "org": "example-io",
        "repo": "example-io/oops",
        "visibility": "private",
    }
)

user_role_updated_github___member_updated = json.dumps(
    {
        "actor": "cat",
        "action": "org.update_member",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
        "user": "bob",
    }
)

user_role_updated_github___member_updated = json.dumps(
    {
        "actor": "cat",
        "action": "org.invite_member",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
        "user": "bob",
    }
)

branch_policy_override_github___branch_protection_policy_override = json.dumps(
    {
        "actor": "cat",
        "action": "protected_branch.policy_override",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "org": "my-org",
        "repo": "my-org/my-repo",
    }
)

branch_policy_override_github___protected_branch_name_updated = json.dumps(
    {
        "actor": "cat",
        "action": "protected_branch.update_name",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)

org_auth_modified_github___authentication_method_changed = json.dumps(
    {
        "actor": "cat",
        "action": "org.saml_disabled",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "org": "my-org",
        "repo": "my-org/my-repo",
    }
)

org_auth_modified_github___non_auth_related_org_change = json.dumps(
    {
        "actor": "cat",
        "action": "invite_member",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)

org_ip_allowlist_github___ip_allow_list_modified = json.dumps(
    {
        "actor": "cat",
        "action": "ip_allow_list_entry.create",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "org": "my-org",
    }
)

org_ip_allowlist_github___ip_allow_list_disabled = json.dumps(
    {
        "actor": "cat",
        "action": "ip_allow_list.disable",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
    }
)

org_ip_allowlist_github___non_ip_allow_list_action = json.dumps(
    {
        "actor": "cat",
        "action": "org.invite_user",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
    }
)

organization_app_integration_installed_app_integration_installation = json.dumps(
    {
        "_document_id": "A-2345",
        "action": "integration_installation.create",
        "actor": "user_name",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-11 05:28:05.542",
        "created_at": "2022-12-11 05:28:05.542",
        "name": "Microsoft Teams for GitHub",
        "org": "your-organization",
        "p_any_usernames": ["user_name"],
    }
)

organization_app_integration_installed_app_integration_installation_2 = json.dumps(
    {
        "_document_id": "A-1234",
        "action": "integration_installation.create",
        "actor": "leetboy",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-02 17:40:08.671",
        "created_at": "2022-12-02 17:40:08.671",
        "name": "Datadog CI",
        "org": "example-io",
    }
)

organization_app_integration_installed_repository_archived = json.dumps(
    {
        "action": "repo.archived",
        "actor": "cat",
        "created_at": 1621305118553.0,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)

branch_protection_disabled_github___branch_protection_disabled = json.dumps(
    {
        "actor": "cat",
        "action": "protected_branch.destroy",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)

branch_protection_disabled_github___protected_branch_name_updated = json.dumps(
    {
        "actor": "cat",
        "action": "protected_branch.update_name",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)

repo_created_github___repo_created = json.dumps(
    {
        "actor": "cat",
        "action": "repo.create",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
repo_created_github___repo_archived = json.dumps(
    {
        "actor": "cat",
        "action": "repo.archived",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
repo_collaborator_change_github___collaborator_added = json.dumps(
    {
        "actor": "bob",
        "action": "repo.add_member",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
        "user": "cat",
    }
)
repo_collaborator_change_github___collaborator_removed = json.dumps(
    {
        "actor": "bob",
        "action": "repo.remove_member",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
        "user": "cat",
    }
)
repo_collaborator_change_github___non_member_action = json.dumps(
    {
        "actor": "bob",
        "action": "repo.enable",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
        "user": "cat",
    }
)
team_modified_github___team_deleted = json.dumps(
    {
        "actor": "cat",
        "action": "team.destroy",
        "created_at": 1621305118553,
        "data": {"team": "my-org/my-team"},
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
team_modified_github___team_created = json.dumps(
    {
        "actor": "cat",
        "action": "team.create",
        "created_at": 1621305118553,
        "data": {"team": "my-org/my-team"},
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
team_modified_github___team_add_repository = json.dumps(
    {
        "actor": "cat",
        "action": "team.add_repository",
        "created_at": 1621305118553,
        "data": {"team": "my-org/my-team"},
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
repo_hook_modified_github___webhook_created = json.dumps(
    {
        "actor": "cat",
        "action": "hook.create",
        "data": {
            "hook_id": 111222333444555,
            "events": ["fork", "public", "pull_request", "push", "repository"],
        },
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repository": "my-org/my-repo",
    }
)
repo_hook_modified_github___webhook_deleted = json.dumps(
    {
        "actor": "cat",
        "action": "hook.destroy",
        "data": {
            "hook_id": 111222333444555,
            "events": ["fork", "public", "pull_request", "push", "repository"],
        },
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repository": "my-org/my-repo",
    }
)
repo_hook_modified_github___non_webhook_event = json.dumps(
    {
        "actor": "cat",
        "action": "org.invite_member",
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repository": "my-org/my-repo",
    }
)
secret_scanning_alert_created_github_detected_a_secret = json.dumps(
    {
        "action": "secret_scanning_alert.create",
        "actor": "github",
        "at_sign_timestamp": "2022-09-08 19:34:43.468",
        "created_at": "2022-09-08 19:34:43.468",
        "number": 1792,
        "org": "acme-co",
        "repo": "acme-co/website",
    }
)
secret_scanning_alert_created_unrelated = json.dumps(
    {
        "action": "unrelated.create",
        "actor": "github",
        "at_sign_timestamp": "2022-09-08 19:34:43.468",
        "created_at": "2022-09-08 19:34:43.468",
        "org": "acme-co",
        "repo": "acme-co/website",
    }
)
advanced_security_change_secret_scanning_disabled_on_a_repo = json.dumps(
    {
        "action": "repository_secret_scanning_push_protection.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_secret_scanning_disabled_org_wide = json.dumps(
    {
        "action": "secret_scanning.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_secret_scanning_disabled_for_new_repos = json.dumps(
    {
        "action": "secret_scanning_new_repos.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_dependabot_alerts_disabled_org_wide = json.dumps(
    {
        "action": "dependabot_alerts.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_dependabot_alerts_disabled_on_new_repos = json.dumps(
    {
        "action": "dependabot_alerts_new_repos.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_dependabot_disabled_org_wide = json.dumps(
    {
        "action": "dependabot_security_updates.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_dependabot_disabled_on_new_repos = json.dumps(
    {
        "action": "dependabot_security_updates_new_repos.disable",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_non_github_adv_sec_action = json.dumps(
    {
        "action": "enterprise.config.disable_anonymous_git_access",
        "actor": "bobert",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-08-16 16:56:49.309",
        "created_at": "2022-08-16 16:56:49.309",
        "org": "an-org",
        "repo": "an-org/a-repo",
        "user": "bobert",
    }
)
advanced_security_change_enterprise_log_business_advanced_security_enabled = json.dumps(
    {
        "@timestamp": 1671111111111,
        "_document_id": "gAcccccccccccccccccccc",
        "action": "business_advanced_security.enabled",
        "actor": "bobert",
        "actor_ip": "12.12.12.12",
        "actor_location": {"country_code": "US"},
        "business": "example-enterprise",
        "created_at": 1671111111111,
        "operation_type": "modify",
        "user": "bobert",
    }
)
advanced_security_change_enterprise_log_business_advanced_security_disabled = (
    json.dumps(
        {
            "@timestamp": 1671111111111,
            "_document_id": "gAcccccccccccccccccccc",
            "action": "business_advanced_security.disabled",
            "actor": "bobert",
            "actor_ip": "12.12.12.12",
            "actor_location": {"country_code": "US"},
            "business": "example-enterprise",
            "created_at": 1671111111111,
            "operation_type": "modify",
            "user": "bobert",
        }
    )
)
org_modified_github___team_deleted = json.dumps(
    {
        "actor": "cat",
        "action": "team.destroy",
        "created_at": 1621305118553,
        "data": {"team": "my-org/my-team"},
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
org_modified_github___org___user_added = json.dumps(
    {
        "actor": "cat",
        "action": "org.add_member",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "user": "cat",
    }
)
org_modified_github___org___user_removed = json.dumps(
    {
        "actor": "cat",
        "action": "org.remove_member",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "user": "bob",
    }
)
repository_transfer_public_repo_created = json.dumps(
    {
        "_document_id": "abCD",
        "action": "repo.create",
        "actor": "example-actor",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-11 22:40:20.268",
        "created_at": "2022-12-11 22:40:20.268",
        "org": "example-io",
        "repo": "example-io/oops",
        "visibility": "public",
    }
)
repository_transfer_repo_transfer_outgoing = json.dumps(
    {
        "_document_id": "BodJtQIrT3kWMIQpm1ANew",
        "action": "repo.transfer_outgoing",
        "actor": "user-name",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-14 19:16:31.299",
        "created_at": "2022-12-14 19:16:31.299",
        "org": "your-organization",
        "repo": "your-organizatoin/project_repo",
        "visibility": "private",
    }
)
repository_transfer_repo_transfer_start = json.dumps(
    {
        "_document_id": "BodJtQIrT3kWMIQpm1ANew",
        "action": "repo.transfer_start",
        "actor": "user-name",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-14 19:16:31.299",
        "created_at": "2022-12-14 19:16:31.299",
        "org": "your-organization",
        "repo": "your-organizatoin/project_repo",
        "visibility": "private",
    }
)
repository_transfer_repository_transfer = json.dumps(
    {
        "_document_id": "CFyS8UJsQjJfCgsmTLI6mQ",
        "action": "repo.transfer",
        "actor": "org-user",
        "actor_location": {"country_code": "US"},
        "at_sign_timestamp": "2022-12-14 19:21:01.035",
        "created_at": "2022-12-14 19:21:01.035",
        "org": "your-organization",
        "repo": "your-organization/project_repo",
        "visibility": "private",
    }
)
repo_visibility_change_github___repo_visibility_change = json.dumps(
    {
        "actor": "cat",
        "action": "repo.access",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
repo_visibility_change_github___repo_disabled = json.dumps(
    {
        "actor": "cat",
        "action": "repo.disable",
        "created_at": 1621305118553,
        "org": "my-org",
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
user_access_key_created_github___user_access_key_created = json.dumps(
    {
        "actor": "cat",
        "action": "public_key.create",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
user_access_key_created_github___user_access_key_deleted = json.dumps(
    {
        "actor": "cat",
        "action": "public_key.delete",
        "created_at": 1621305118553,
        "p_log_type": "GitHub.Audit",
        "repo": "my-org/my-repo",
    }
)
