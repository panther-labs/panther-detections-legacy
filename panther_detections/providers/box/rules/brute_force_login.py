import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags


def brute_force_login(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Box user was denied access more times than the configured threshold."""

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.deep_get('source', 'name', default='<UNKNOWN_USER>')}]"
            f" has exceeded the failed login threshold."
        )

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="--DEPRECATED -- Box Brute Force Login",
        rule_id="Box.Brute.Force.Login",
        log_types=[schema.LogTypeBoxEvent],
        severity=detection.SeverityMedium,
        description="A Box user was denied access more times than the configured threshold.",
        tags=rule_tags(),
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Analyze the IP they came from, and other actions taken before/after. "
        "Check if this user eventually authenticated successfully.",
        alert_title=_title,
        summary_attrs=["event_type", "ip_address"],
        threshold=10,
        alert_grouping=detection.AlertGrouping(period_minutes=10),
        filters=(pre_filters or []) + [match_filters.deep_equal("event_type", "FAILED_LOGIN")],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Regular Event", expect_match=False, data=sample_logs.regular_event),
                detection.JSONUnitTest(name="Login Failed", expect_match=True, data=sample_logs.login_failed),
            ]
        ),
    )
