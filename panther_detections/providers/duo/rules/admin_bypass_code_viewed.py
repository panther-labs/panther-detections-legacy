import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs


def admin_bypass_code_viewed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """An administrator viewed the MFA bypass code for a user."""

    def _title(event: PantherEvent) -> str:

        return (
            f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed "
            f"an MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]."
        )

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin Bypass Code Viewed",
        rule_id="Duo.Admin.Bypass.Code.Viewed",
        log_types=["Duo.Administrator"],
        severity=detection.SeverityMedium,
        description="An administrator viewed the MFA bypass code for a user.",
        reference="https://duo.com/docs/adminapi",
        runbook="Confirm this behavior is authorized. The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. You should not share it with unauthorized individuals or email it to anyone under any circumstances!",
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "bypass_view")],
        alert_title=_title,
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Bypass View", expect_match=True, data=sample_logs.admin_bypass_code_viewed_bypass_view
                ),
                detection.JSONUnitTest(
                    name="Bypass Create", expect_match=False, data=sample_logs.admin_bypass_code_viewed_bypass_create
                ),
            ]
        ),
        alert_grouping=detection.AlertGrouping(period_minutes=60),
    )
