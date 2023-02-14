from typing import List

from panther_sdk import detection

from . import rules
from ._shared import *
from .sample_logs import *

# from panther_detections.datamodels import github_audit


def use_all_with_defaults() -> List[detection.Rule]:
    return [
        rules.advanced_security_change(),
        rules.branch_policy_override(),
        rules.branch_protection_disabled(),
        rules.org_auth_modified(),
        rules.org_ip_allowlist(),
        rules.org_modified(),
        rules.organization_app_integration_installed(),
        rules.public_repository_created(),
        rules.repo_collaborator_change(),
        rules.repo_created(),
        rules.repo_hook_modified(),
        rules.repo_visibility_change(),
        rules.repository_transfer(),
        rules.secret_scanning_alert_created(),
        rules.team_modified(),
        rules.user_access_key_created(),
        rules.user_role_updated(),
    ]
