import json

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags


def admin_lockout(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """Alert when a duo administrator is locked out of their account."""

    def _title(event: PantherEvent) -> str:
        # If no 'dedup' function is defined, the return value
        # of this method will act as deduplication string.
        try:
            desc = json.loads(event.get("description", {}))
            message = desc.get("message", "<NO_MESSAGE_FOUND>")[:-1]
        except ValueError:
            message = "Invalid Json"
        return f"Duo Admin [{event.get('username', '<NO_USER_FOUND>')}] is " f"locked out. Reason: [{message}]."

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Duo Admin Lockout",
        rule_id="Duo.Admin.Lockout",
        log_types=[schema.LogTypeDuoAdministrator],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="Alert when a duo administrator is locked out of their account.",
        reference="https://duo.com/docs/adminapi",
        filters=[match_filters.deep_equal("action", "admin_lockout")],
        alert_title=_title,
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin lockout- invalid json",
                    expect_match=True,
                    data=sample_logs.admin_lockout_admin_lockout__invalid_json,
                ),
                detection.JSONUnitTest(
                    name="Admin lockout- valid json",
                    expect_match=True,
                    data=sample_logs.admin_lockout_admin_lockout__valid_json,
                ),
                detection.JSONUnitTest(
                    name="Bypass Create", expect_match=False, data=sample_logs.admin_lockout_bypass_create
                ),
            ]
        ),
        alert_grouping=detection.AlertGrouping(period_minutes=60),
    )
