import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["workspace_calendar_external_sharing"]


def workspace_calendar_external_sharing(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Changed The Sharing Settings for Primary Calendars"""
    # from panther_base_helpers import deep_get

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get

            if not all(
                [
                    (event.get("name", "") == "CHANGE_CALENDAR_SETTING"),
                    (deep_get(event, "parameters", "SETTING_NAME", default="") == "SHARING_OUTSIDE_DOMAIN"),
                ]
            ):
                return False
            return deep_get(event, "parameters", "NEW_VALUE", default="") in [
                "READ_WRITE_ACCESS",
                "READ_ONLY_ACCESS",
                "MANAGE_ACCESS",
            ]

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite workspace setting for default calendar sharing was changed by "
            f"[{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}] "
            f"from [{event.deep_get('parameters', 'OLD_VALUE', default='<NO_OLD_SETTING_FOUND>')}] "
            f"to [{event.deep_get('parameters', 'NEW_VALUE', default='<NO_NEW_SETTING_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Workspace Calendar External Sharing Setting Change",
        rule_id="GSuite.Workspace.CalendarExternalSharingSetting",
        log_types=["GSuite.ActivityEvent"],
        severity=detection.SeverityMedium,
        description="A Workspace Admin Changed The Sharing Settings for Primary Calendars",
        tags=["GSuite"],
        reports={"MITRE ATT&CK": ["TA0007:T1087"]},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-calendar-settings#CHANGE_CALENDAR_SETTING",
        runbook="Restore the calendar sharing setting to the previous value. If unplanned, use indicator search to identify other activity from this administrator.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or []) + [rule_filter()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=True,
                    data=sample_logs.workspace_calendar_external_sharing_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
                    expect_match=True,
                    data=sample_logs.workspace_calendar_external_sharing_admin_set_default_calendar_sharing_outside_domain_setting_to_read_write_access,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=True,
                    data=sample_logs.workspace_calendar_external_sharing_admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access,
                ),
                detection.JSONUnitTest(
                    name="Non-Default Calendar SHARING_OUTSIDE_DOMAIN event",
                    expect_match=False,
                    data=sample_logs.workspace_calendar_external_sharing_non_default_calendar_sharing_outside_domain_event,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_calendar_external_sharing_listobject_type,
                ),
            ]
        ),
    )
