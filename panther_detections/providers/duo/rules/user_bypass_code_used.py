from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import duo_alert_context_ip, rule_tags


def user_bypass_code_used(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Duo user's bypass code was used to authenticate"""

    def _title(event: PantherEvent) -> str:

        user = event.deep_get("user.name", default="Unknown")
        return f"Bypass code for Duo User [{user}] used"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo User Bypass Code Used",
        rule_id="DUO.User.BypassCode.Used",
        log_types=[schema.LogTypeDuoAuthentication],
        tags=rule_tags(),
        severity=detection.SeverityLow,
        description="A Duo user's bypass code was used to authenticate",
        reference="https://duo.com/docs/adminapi#authentication-logs",
        runbook="Follow up with the user to confirm they used the bypass code themselves.",
        filters=[match_filters.deep_equal("reason", "bypass_user"), match_filters.deep_equal("result", "success")],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="bypass_code_used", expect_match=True, data=sample_logs.user_bypass_code_used_bypass_code_used
                ),
                detection.JSONUnitTest(
                    name="good_auth", expect_match=False, data=sample_logs.user_bypass_code_used_good_auth
                ),
                detection.JSONUnitTest(
                    name="denied_old_creds", expect_match=False, data=sample_logs.user_bypass_code_used_denied_old_creds
                ),
            ]
        ),
        alert_context=duo_alert_context_ip,
        alert_grouping=detection.AlertGrouping(period_minutes=5),
    )
