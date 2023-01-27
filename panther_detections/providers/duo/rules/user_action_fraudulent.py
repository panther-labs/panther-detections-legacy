import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import create_alert_context_ip


def user_action_fraudulent(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Alert when a user reports a Duo action as fraudulent."""

    def _title(event: PantherEvent) -> str:

        user = event.deep_get("user.name", default="Unknown")
        return f"A Duo action was marked as fraudulent by [{user}]"

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #     return {
    #         "factor": event.get("factor"),
    #         "reason": event.get("reason"),
    #         "user": event.deep_get("user.name", default=""),
    #         "os": event.deep_get("access_device.os", default=""),
    #         "ip_access": event.deep_get("access_device.ip", default=""),
    #         "ip_auth": event.deep_get("auth_device.ip", default=""),
    #         "application": event.deep_get("application.name", default=""),
    #     }

    return detection.Rule(
        overrides=overrides,
        name="Duo User Action Reported as Fraudulent",
        rule_id="DUO.User.Action.Fraudulent",
        log_types=["Duo.Authentication"],
        tags=["Duo"],
        severity=detection.SeverityMedium,
        description="Alert when a user reports a Duo action as fraudulent.",
        reference="https://duo.com/docs/adminapi#authentication-logs",
        runbook="Follow up with the user to confirm.",
        filters=(pre_filters or []) + [match_filters.deep_equal("result", "fraud")],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(name="user_marked_fraud", expect_match=True, data=sample_logs.user_marked_fraud),
            ]
        ),
        alert_context=create_alert_context_ip,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
    )
