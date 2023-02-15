from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import duo_alert_context_ip, rule_tags


def user_action_fraudulent(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Alert when a user reports a Duo action as fraudulent."""

    def _title(event: PantherEvent) -> str:

        user = event.deep_get("user.name", default="Unknown")
        return f"A Duo action was marked as fraudulent by [{user}]"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo User Action Reported as Fraudulent",
        rule_id="DUO.User.Action.Fraudulent",
        log_types=[schema.LogTypeDuoAuthentication],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="Alert when a user reports a Duo action as fraudulent.",
        reference="https://duo.com/docs/adminapi#authentication-logs",
        runbook="Follow up with the user to confirm.",
        filters=[match_filters.deep_equal("result", "fraud")],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="user_marked_fraud",
                    expect_match=True,
                    data=sample_logs.user_action_fraudulent_user_marked_fraud,
                ),
            ]
        ),
        alert_context=duo_alert_context_ip,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
    )
