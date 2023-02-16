from typing import List

from panther_sdk import PantherEvent

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> List[PantherEvent]:
    return [
        rules.saml_modified(),
        rules.user_modified(),
        rules.detection_deleted(),
        rules.sensitive_role_created(),
    ]
