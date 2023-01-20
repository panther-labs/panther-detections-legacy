import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_workspace_calendar_external_sharing(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Changed The Sharing Settings for Primary Calendars"""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Workspace Calendar External Sharing Setting Change",
        rule_id="GSuite.Workspace.CalendarExternalSharingSetting",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports={'MITRE ATT&CK': ['TA0007:T1087']},
        severity=detection.SeverityMedium,
        description="A Workspace Admin Changed The Sharing Settings for Primary Calendars",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-calendar-settings#CHANGE_CALENDAR_SETTING",
        runbook="Restore the calendar sharing setting to the previous value. If unplanned, use indicator search to identify other activity from this administrator.",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['actor:email']
        ,
        threshold="",
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=True,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
                    expect_match=True,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_write_access
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to MANAGE_ACCESS",
                    expect_match=True,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_manage_access
                ),
                detection.JSONUnitTest(
                    name="Non-Default Calendar SHARING_OUTSIDE_DOMAIN event",
                    expect_match=False,
                    data=sample_logs.non_default_calendar_sharing_outside_domain_event
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type
                ),
                
            ]
        )
    )