from typing import Literal

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.admin_app_integration_secret_key_viewed()
    rules.admin_bypass_code_created()
    rules.admin_bypass_code_viewed()
    rules.admin_create_admin()
    rules.admin_lockout()
    rules.admin_marked_push_fraudulent()
    rules.admin_mfa_restrictions_updated()
    rules.admin_new_admin_api_app_integration()
    rules.admin_policy_updated()
    rules.admin_sso_saml_requirement_disabled()
    rules.admin_user_mfa_bypass_enabled()
    rules.user_action_fraudulent()
    rules.user_anomalous_push()
    rules.user_bypass_code_used()
    rules.user_endpoint_failure_multi()
