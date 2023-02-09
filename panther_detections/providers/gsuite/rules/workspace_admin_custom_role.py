import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_admin_custom_role"]


def workspace_admin_custom_role(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google Workspace administrator created a new custom administrator role."""

    def _title(event: PantherEvent) -> str:
        # (Optional) Return a string which will be shown as the alert title.
        # If no 'dedup' function is defined, the return value of this method
        # will act as deduplication string.
        return (
            f"Google Workspace Administrator "
            f"[{event.get('actor',{}).get('email','NO_EMAIL_FOUND')}] "
            f"created a new admin role "
            f"[{event.get('parameters',{}).get('ROLE_NAME','NO_ROLE_NAME_FOUND')}]."
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Google Workspace Admin Custom Role",
        rule_id="Google.Workspace.Admin.Custom.Role",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A Google Workspace administrator created a new custom administrator role.",
        tags=rule_tags("admin", "administrator", "google workspace", "role"),
        # reports=,
        # reference=,
        runbook="Please review this activity with the administrator and ensure this behavior was authorized.",
        alert_title=_title,
        summary_attrs=["actor.email", "name", "type"],
        threshold=1,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("type", "DELEGATED_ADMIN_SETTINGS"),
            match_filters.deep_equal("name", "CREATE_ROLE"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Delete Role",
                    expect_match=False,
                    data=sample_logs.workspace_admin_custom_role_delete_role,
                ),
                detection.JSONUnitTest(
                    name="New Custom Role Created",
                    expect_match=True,
                    data=sample_logs.workspace_admin_custom_role_new_custom_role_created,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_admin_custom_role_listobject_type,
                ),
            ]
        ),
    )
