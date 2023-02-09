import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_calendar_external_sharing"]


def workspace_calendar_external_sharing(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Changed The Sharing Settings for Primary Calendars"""

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
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A Workspace Admin Changed The Sharing Settings for Primary Calendars",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0007:T1087"]},
        # pylint: disable=line-too-long
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-calendar-settings#CHANGE_CALENDAR_SETTING",
        runbook="Restore the calendar sharing setting to the previous value."
        "If unplanned, use indicator search to identify other activity from this administrator.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("name", "CHANGE_CALENDAR_SETTING"),
            match_filters.deep_equal("parameters.SETTING_NAME", "SHARING_OUTSIDE_DOMAIN"),
            match_filters.deep_in(
                "parameters.NEW_VALUE",
                {"READ_WRITE_ACCESS", "READ_ONLY_ACCESS", "MANAGE_ACCESS"},
            ),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=True,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
                    expect_match=True,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_write_access,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=True,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access,
                ),
                detection.JSONUnitTest(
                    name="Non-Default Calendar SHARING_OUTSIDE_DOMAIN event",
                    expect_match=False,
                    data=sample_logs.non_default_calendar_sharing_outside_domain_event,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type,
                ),
            ]
        ),
    )
