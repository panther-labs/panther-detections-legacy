from typing import Literal

from . import rules
from ._shared import *


def use_all_with_defaults() -> None:
    rules.gsuite_calendar_made_public()
    rules.gsuite_leaked_password()
    rules.gsuite_advanced_protection()
    rules.gsuite_brute_force_login()
    rules.gsuite_device_compromised()
    rules.gsuite_device_suspicious_activity()
    # rules.gsuite_drive_overly_visibly()
    rules.gsuite_external_forwarding()
    rules.gsuite_gov_attack()
    rules.gsuite_group_banned_user()
    rules.gsuite_leaked_password()
    rules.gsuite_login_type()
    # rules.gsuite_mobile_device_screen_unlock_fail()
    rules.gsuite_passthrough_rule()
    rules.gsuite_suspicious_logins()
    # rules.gsuite_two_step_verification()
    rules.gsuite_user_suspended()
