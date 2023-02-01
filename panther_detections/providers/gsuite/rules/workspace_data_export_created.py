import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["workspace_data_export_created"]


def workspace_data_export_created(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Created a Data Export"""
    # from panther_base_helpers import deep_get

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            return event.get("name", "").startswith("CUSTOMER_TAKEOUT_")

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Workspace Data Export "
            f"[{event.get('name', '<NO_EVENT_NAME>')}] "
            f"performed by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Workspace Data Export Has Been Created",
        rule_id="GSuite.Workspace.DataExportCreated",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Created a Data Export",
        tags=["GSuite"],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/data-studio#DATA_EXPORT",
        runbook="Verify the intent of this Data Export. If intent cannot be verified, then a search on the actor's other activities is advised.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or []) + [rule_filter()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Data Export Created",
                    expect_match=True,
                    data=sample_logs.workspace_data_export_created_workspace_admin_data_export_created,
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Data Export Succeeded",
                    expect_match=True,
                    data=sample_logs.workspace_data_export_created_workspace_admin_data_export_succeeded,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=False,
                    data=sample_logs.workspace_data_export_created_admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_data_export_created_listobject_type,
                ),
            ]
        ),
    )
