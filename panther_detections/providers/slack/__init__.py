from typing import Literal

from . import queries, rules, sample_logs
from ._shared import *

def use_all_with_defaults() -> None:
    rules.legal_hold_policy_modified()
    rules.app_access_expanded()
    rules.information_barrier_modified()
    rules.passthrough_anomaly()
    rules.user_privilege_escalation()
    rules.private_channel_made_public()
    rules.org_deleted()
    rules.mfa_settings_changed()
    rules.service_owner_transferred()
    rules.potentially_malicious_file_shared()
    rules.ekm_config_changed()
    rules.ekm_slackbot_unenrolled()
    rules.intune_mdm_disabled()
    rules.ekm_unenrolled()
    rules.sso_settings_changed()
    rules.idp_configuration_change()
    rules.org_created()
    rules.app_removed()
    rules.app_added()
    rules.dlp_modified()
    rules.application_dos()
