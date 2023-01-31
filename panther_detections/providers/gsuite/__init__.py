from typing import Literal

from . import rules
from ._shared import *


# def use_reports_events_with_defaults() -> None:
#     rules.drive_overly_visible()
#     rules.drive_external_share()
#     rules.drive_visibility_change()


def use_activityevents_with_defaults() -> None:
    rules.calendar_made_public()
    rules.leaked_password()
    rules.advanced_protection()
    rules.device_compromised()
    rules.device_suspicious_activity()
    rules.external_forwarding()
    rules.gov_attack()
    rules.group_banned_user()
    rules.leaked_password()
    rules.login_type()
    # rules.mobile_device_screen_unlock_fail()
    rules.passthrough_rule()
    rules.suspicious_logins()
    # rules.two_step_verification()
    rules.user_suspended()
    rules.workspace_admin_custom_role()
    rules.workspace_advanced_protection_program()
    rules.workspace_apps_marketplace_allowlist()
    rules.workspace_apps_marketplace_new_domain_application()
    rules.workspace_apps_new_mobile_app_installed()
    rules.workspace_calendar_external_sharing()
    rules.workspace_data_export_created()
    rules.workspace_gmail_default_routing_rule()
    rules.workspace_gmail_enhanced_predelivery_scanning()
    rules.workspace_gmail_security_sandbox_disabled()
    rules.workspace_password_enforce_strong_disabled()
    rules.workspace_password_reuse_enabled()
    rules.workspace_trusted_domains_allowlist()
