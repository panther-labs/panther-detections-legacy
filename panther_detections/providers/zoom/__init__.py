from typing import Literal

from . import rules, sample_logs

def use_all_with_defaults() -> None:
    rules.user_promoted_to_privileged_role()
    rules.operation_passcode_disabled()
    rules.all_meetings_secured_with_one_option_disabled()
    rules.automatic_sign_out_disabled()
