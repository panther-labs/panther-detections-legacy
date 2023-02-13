from typing import Literal

from . import rules, sample_logs
from ._shared import *
from .data_model import *


def use_all_with_defaults() -> None:
    rules.advanced_security_change()
    rules.branch_policy_override()
    rules.branch_protection_disabled()
    rules.org_auth_modified()
    # rules.org_ip_allowlist()
    # rules.org_modified()
    # rules.organization_app_integration_installed()
    # rules.public_repository_created()
    # rules.repo_collaborator_change()
    # rules.repo_created()
    # rules.repo_hook_modified()
    # rules.repo_initial_access()
    # rules.repo_visibility_change()
    # rules.repository_transfer()
    # rules.secret_scanning_alert_created()
    # rules.team_modified()
    # rules.user_access_key_created()
    # rules.user_role_updated()
