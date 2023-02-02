from typing import Literal

from . import queries, rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.user_logged_in_as_user()