import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = [
    "application_dos"
]


def application_dos(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when slack admin invalidates user session(s) more than once in a 24 hour period which can lead to DoS"""
        #from datetime import datetime, timedelta
    #from json import dumps
    #from panther_base_helpers import deep_get, slack_alert_context
    #from panther_oss_helpers import get_string_set, put_string_set, set_key_expiration
    #DENIAL_OF_SERVICE_ACTIONS = [
    #    "bulk_session_reset_by_admin",
    #    "user_session_invalidated",
    #    "user_session_reset_by_admin",
    #]

    
    
    
    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    return slack_alert_context(event)

    
    
     
    
                  
    return detection.Rule(
        overrides=overrides,
        #enabled=,
        name="Slack Denial of Service",
        rule_id="Slack.AuditLogs.ApplicationDoS",
        log_types=['Slack.AuditLogs'],
        severity=detection.SeverityCritical,
        description="Detects when slack admin invalidates user session(s) more than once in a 24 hour period which can lead to DoS",
        tags=['Slack'],
        #reports=,
        reference="https://api.slack.com/admins/audit-logs",
        #runbook=,
        alert_title=_title,
        summary_attrs=['action', 'p_any_ip_addresses', 'p_any_emails'],
        threshold=60,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            # def rule(event):
    #    # Only evaluate actions that could be used for a DoS
    #    if event.get("action") not in DENIAL_OF_SERVICE_ACTIONS:
    #        return False
    #    # Generate a unique cache key for each user
    #    user_key = gen_key(event)
    #    # Retrieve prior entries from the cache, if any
    #    last_reset = get_string_set(user_key)
    #    # Store the reset info for future use
    #    store_reset_info(user_key, event)
    #    # If this is the first reset for the user, don't alert
    #    if not last_reset:
    #        return False
    #    return True

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User Session Reset - First time",
                    expect_match=False,
                    data=sample_logs.application_dos_user_session_reset___first_time
                ),
                detection.JSONUnitTest(
                    name="User Session Reset - Multiple Times",
                    expect_match=True,
                    data=sample_logs.application_dos_user_session_reset___multiple_times
                ),
                
            ]
        )
    )