from typing import Literal

from . import queries, rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.calendar_made_public()
    rules.passthrough_rule()
