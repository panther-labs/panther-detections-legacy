from typing import Literal

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.user_promoted_to_privileged_role()
    rules.operation_passcode_disabled()
    rules.operation_user_granted_admin_deprecated()
