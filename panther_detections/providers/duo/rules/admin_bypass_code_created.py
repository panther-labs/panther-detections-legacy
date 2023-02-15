from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags


def admin_bypass_code_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Duo administrator created an MFA bypass code for an application."""

    def _title(event: PantherEvent) -> str:

        return (
            f"Duo: [{event.get('username', '<NO_USER_FOUND>')}] created "
            f"a MFA bypass code for [{event.get('object', '<NO_OBJECT_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo Admin Bypass Code Created",
        rule_id="Duo.Admin.Bypass.Code.Created",
        log_types=[schema.LogTypeDuoAdministrator],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="A Duo administrator created an MFA bypass code for an application.",
        runbook="Confirm this was authorized and necessary behavior.",
        filters=[match_filters.deep_equal("action", "bypass_create")],
        alert_title=_title,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Bypass Create", expect_match=True, data=sample_logs.admin_bypass_code_created_bypass_create
                ),
                detection.JSONUnitTest(
                    name="Bypass Delete", expect_match=False, data=sample_logs.admin_bypass_code_created_bypass_delete
                ),
            ]
        ),
        threshold=1,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
    )
