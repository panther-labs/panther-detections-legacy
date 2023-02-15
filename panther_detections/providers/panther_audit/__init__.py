from typing import Literal, List
from panther_sdk import detection

from . import queries, rules, sample_logs
from ._shared import *

def use_all_with_defaults(List[detection.Rule]) -> None:
    return [
        rules.saml_modified(),
        rules.user_modified(),
        rules.detection_deleted(),
        rules.sensitive_role_created()
    ]
