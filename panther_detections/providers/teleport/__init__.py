from typing import List, Literal, Union

from panther_sdk import detection

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> List[Union[detection.Rule]]:
    return [
        rules.auth_errors(),
        rules.create_user_accounts(),
        rules.network_scanning(),
        rules.scheduled_jobs(),
        rules.suspicious_commands(),
    ]
