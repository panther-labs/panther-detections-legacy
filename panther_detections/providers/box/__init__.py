from typing import Literal

from . import rules, sample_logs
from ._shared import *


def use_all_with_defaults() -> None:
    rules.access_granted()
    # rules.anomalous_download() #WIP Failing
    rules.brute_force_login()
    rules.event_triggered_externally()
    rules.item_shared_externally()
    # rules.malicious_content()
    rules.new_login()
    rules.policy_violation()
    # rules.suspicious_login_or_session()
    rules.untrusted_device()
    rules.user_downloads()
    rules.user_permission_updates()
