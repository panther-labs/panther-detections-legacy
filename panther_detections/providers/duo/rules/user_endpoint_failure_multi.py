from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import ENDPOINT_REASONS, duo_alert_context_ip, rule_tags


def user_endpoint_failure_multi(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Duo user's authentication was denied due to a suspicious error on the endpoint"""

    def _title(event: PantherEvent) -> str:

        user = event.deep_get("user.name", default="Unknown")
        reason = event.get("reason", "Unknown")
        return f"Duo User [{user}] encountered suspicious endpoint issue [{reason}]"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo User Denied For Endpoint Error",
        rule_id="DUO.User.Endpoint.Failure",
        log_types=[schema.LogTypeDuoAuthentication],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="A Duo user's authentication was denied due to a suspicious error on the endpoint",
        reference="https://duo.com/docs/adminapi#authentication-logs",
        runbook="Follow up with the endpoint owner to see status. Follow up with user to verify attempts.",
        filters=[match_filters.deep_in("reason", ENDPOINT_REASONS)],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="endpoint_is_not_in_management_system",
                    expect_match=True,
                    data=sample_logs.user_endpoint_failure_multi_endpoint_is_not_in_management_system,
                ),
                detection.JSONUnitTest(
                    name="endpoint_failed_google_verification",
                    expect_match=True,
                    data=sample_logs.user_endpoint_failure_multi_endpoint_failed_google_verification,
                ),
                detection.JSONUnitTest(
                    name="endpoint_is_not_trusted",
                    expect_match=True,
                    data=sample_logs.user_endpoint_failure_multi_endpoint_is_not_trusted,
                ),
                detection.JSONUnitTest(
                    name="could_not_determine_if_endpoint_was_trusted",
                    expect_match=True,
                    data=sample_logs.user_endpoint_failure_multi_could_not_determine_if_endpoint_was_trusted,
                ),
                detection.JSONUnitTest(
                    name="invalid_device",
                    expect_match=True,
                    data=sample_logs.user_endpoint_failure_multi_invalid_device,
                ),
                detection.JSONUnitTest(
                    name="good_auth", expect_match=False, data=sample_logs.user_endpoint_failure_multi_good_auth
                ),
                detection.JSONUnitTest(
                    name="denied_old_creds",
                    expect_match=False,
                    data=sample_logs.user_endpoint_failure_multi_denied_old_creds,
                ),
            ]
        ),
        alert_context=duo_alert_context_ip,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
    )
