import typing

from panther_core import PantherEvent
from panther_sdk import detection

from panther_detections.providers.gsuite import sample_logs
from panther_detections.providers.gsuite._shared import (
    ACTIVITY_LOG_TYPE,
    REPORTS_LOG_TYPE,
    SHARED_SUMMARY_ATTRS,
    create_alert_context,
    rule_tags,
)
from panther_detections.utils import match_filters, standard_tags

__all__ = ["calendar_made_public"]


def calendar_made_public(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """GSuite Calendar Made Public"""

    def _title(event: PantherEvent) -> str:
        return f"GSuite calendar [{event.deep_get('parameters', 'calendar_id', default='<NO_CALENDAR_ID>')}] made public by [{event.deep_get('actor', 'email', default='<NO_ACTOR_FOUND>')}]"

    return detection.Rule(
        overrides=overrides,
        name="GSuite Calendar Made Public",
        rule_id="GSuite.CalendarMadePublic",
        log_types=[ACTIVITY_LOG_TYPE],
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="A user or admin has modified a calendar to be public",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/calendar#change_calendar_acls",
        runbook="Follow up with user about this calendar share.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("name", "change_calendar_acls"),
            match_filters.deep_equal(
                "parameters.grantee_email", "__public_principal__@public.calendar.google.com"),
        ],
        alert_title=_title,
        alert_context=create_alert_context,
        summary_attrs=SHARED_SUMMARY_ATTRS,
        unit_tests=[
            detection.JSONUnitTest(
                name="User publicly shared calendar",
                expect_match=True,
                data=sample_logs.user_publicly_shared_calendar,
            ),
            detection.JSONUnitTest(
                name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_WRITE_ACCESS",
                expect_match=False,
                data=sample_logs.admin_set_default_cal_setting,
            ),
            detection.JSONUnitTest(
                name="List Object Type",
                expect_match=False,
                data=sample_logs.list_object_type,
            ),
        ],
    )
