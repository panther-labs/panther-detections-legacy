import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import create_alert_context_ip


def user_anomalous_push(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Duo authentication was denied due to an anomalous 2FA push."""

    def _title(event: PantherEvent) -> str:

        user = event.deep_get("user.name", default="Unknown")
        return f"Duo Auth denied due to an anomalous 2FA push for [{user}]"

    return detection.Rule(
        overrides=overrides,
        name="Duo User Auth Denied For Anomalous Push",
        rule_id="DUO.User.Denied.AnomalousPush",
        log_types=["Duo.Authentication"],
        tags=["Duo"],
        severity=detection.SeverityMedium,
        description="A Duo authentication was denied due to an anomalous 2FA push.",
        reference="https://duo.com/docs/adminapi#authentication-logs",
        runbook="Follow up with the user to confirm they intended several pushes in quick succession.",
        filters=(pre_filters or [])
        + [match_filters.deep_equal("reason", "anomalous_push"), match_filters.deep_equal("result", "denied")],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="anomalous_push_occurred", expect_match=True, data=sample_logs.anomalous_push_occurred
                ),
                detection.JSONUnitTest(name="good_auth", expect_match=False, data=sample_logs.good_auth),
                detection.JSONUnitTest(name="denied_old_creds", expect_match=False, data=sample_logs.denied_old_creds),
            ]
        ),
        alert_context=create_alert_context_ip,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
    )
