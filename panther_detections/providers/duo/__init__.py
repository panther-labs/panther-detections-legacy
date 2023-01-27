from typing import Literal

from . import queries, rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.admin_create_admin()
    rules.admin_app_integration_secret_key_viewed()
    rules.admin_bypass_code_created()
    rules.admin_bypass_code_viewed()
