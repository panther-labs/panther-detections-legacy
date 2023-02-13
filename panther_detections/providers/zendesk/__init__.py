from typing import Literal

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.mobile_app_access()
    rules.new_api_token()
    rules.new_owner()
    rules.sensitive_data_redaction()
    rules.user_assumption()
    rules.user_role() #(WIP) fix udm
    rules.user_suspension()
