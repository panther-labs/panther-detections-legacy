from typing import Literal

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.auth_errors()
    rules.create_user_accounts()
    rules.network_scanning()
    rules.scheduled_jobs()
    rules.suspicious_commands()
