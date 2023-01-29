import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    get_zoom_usergroup_context
)

def operation_passcode_disabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Meeting passcode requirement has been disabled from usergroup"""

    def _title(event: PantherEvent) -> str:
       context = get_zoom_usergroup_context(event)
       return f"Group {context['GroupName']} passcode requirement disabled by {event.get('operator')}"

    def _filter_func(event: PantherEvent) -> bool:
       context = get_zoom_usergroup_context(event)
       return "Passcode" in context["Change"] and context["DisabledSetting"]

    return detection.Rule(
        overrides=overrides,
        name="Zoom Meeting Passcode Disabled",
        rule_id="Zoom.PasscodeDisabled",
        log_types=['Zoom.Operation'],
        severity=detection.SeverityLow,
        description="Meeting passcode requirement has been disabled from usergroup",
        tags=['Zoom', 'Collection:Video Capture'],
        reports={'MITRE ATT&CK': ['TA0009:T1125']},
        reference="https://support.zoom.us/hc/en-us/articles/360033559832-Zoom-Meeting-and-Webinar-passcodes",
        runbook="Follow up with user or Zoom admin to ensure this meeting room's use case does not allow a passcode.",
        alert_title=_title,
        summary_attrs=['p_any_emails'],
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("category_type", "User Group"),
            detection.PythonFilter(func=_filter_func)
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Meeting Passcode Disabled",
                    expect_match=True,
                    data=sample_logs.meeting_passcode_disabled
                ),
                detection.JSONUnitTest(
                    name="Meeting Passcode Enabled",
                    expect_match=False,
                    data=sample_logs.meeting_passcode_enabled
                ),
                
            ]
        )
    )