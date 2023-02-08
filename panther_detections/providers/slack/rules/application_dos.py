import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters
from panther_detections.utils.dynamo_utils import (
    get_string_set,
    put_string_set,
    set_key_expiration,
)

from .. import sample_logs
from .._shared import (
    DENIAL_OF_SERVICE_ACTIONS,
    gen_key,
    rule_tags,
    slack_alert_context,
    store_reset_info,
)

__all__ = ["application_dos"]


def application_ddos_filter() -> detection.PythonFilter:
    def _application_ddos_filter(event: PantherEvent) -> bool:
        from datetime import datetime, timedelta
        from json import dumps

        from panther_detections.utils.dynamo_utils import (
            get_string_set,
            put_string_set,
            set_key_expiration,
        )

        def gen_key(event: PantherEvent) -> str:
            return f"Slack.AuditLogs.ApplicationDoS{event.deep_get('entity', 'user', 'name')}"

        def store_reset_info(key, event) -> None:
            # Map the user to the most recent reset
            put_string_set(
                key,
                [
                    dumps(
                        {
                            "time": event.get("p_event_time"),
                        }
                    )
                ],
            )
            # Expire the entry after 24 hours
            set_key_expiration(key, str((datetime.now() + timedelta(days=1)).timestamp()))

        # Generate a unique cache key for each user
        user_key = gen_key(event)
        # Retrieve prior entries from the cache, if any
        last_reset = get_string_set(user_key)
        # Store the reset info for future use
        store_reset_info(user_key, event)
        # If this is the first reset for the user, don't alert
        if not last_reset:
            return False
        return True

    return detection.PythonFilter(func=_application_ddos_filter)


def application_dos(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when slack admin invalidates user session(s) more than once in a 24 hour period which can lead to DoS"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Denial of Service",
        rule_id="Slack.AuditLogs.ApplicationDoS",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityCritical,
        description="Detects when slack admin invalidates user session(s) more "
        "than once in a 24 hour period which can lead to DoS",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["action", "p_any_ip_addresses", "p_any_emails"],
        threshold=60,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [match_filters.deep_in("action", DENIAL_OF_SERVICE_ACTIONS), application_ddos_filter()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User Session Reset - First time",
                    expect_match=False,
                    data=sample_logs.application_dos_user_session_reset___first_time,
                ),
                detection.JSONUnitTest(
                    name="User Session Reset - Multiple Times",
                    expect_match=True,
                    data=sample_logs.application_dos_user_session_reset___multiple_times,
                ),
            ]
        ),
    )
