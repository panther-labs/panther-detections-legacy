from typing import Literal

from . import rules
from ._shared import *


def use_all_with_defaults() -> None:
    rules.unusual_client()
    rules.sensitive_item_access()
