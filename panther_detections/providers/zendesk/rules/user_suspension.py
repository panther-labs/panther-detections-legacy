import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    ZENDESK_CHANGE_DESCRIPTION
)

def user_suspension(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user's Zendesk suspension status was changed."""
    USER_SUSPENSION_ACTIONS = [
       "create",
       "update",
    ]

    def _title(event: PantherEvent) -> str:
       suspension_status = event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower()
       user = event.get("source_label", "<UNKNOWN_USER>").split(":")
       if len(user) > 1:
           user = user[1].strip()
       return f"Actor user [{event.udm('actor_user')}] {suspension_status} user [{user}]"

    def _severity(event: PantherEvent) -> str:
       if event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower() == "suspended":
           return "INFO"
       return "HIGH"

    def suspended_filter(event: PantherEvent) -> bool:
        return ("suspended" in event.get(ZENDESK_CHANGE_DESCRIPTION, "").lower())

    return detection.Rule(
        overrides=overrides,
        name="Zendesk User Suspension Status Changed",
        rule_id="Zendesk.UserSuspension",
        log_types=['Zendesk.Audit'],
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityHigh),
        description="A user's Zendesk suspension status was changed.",
        tags=['Zendesk', 'Impact:Account Access Removal'],
        reports={'MITRE ATT&CK': ['TA0040:T1531']},
        runbook="Ensure the user's suspension status is appropriate.",
        alert_title=_title,
        summary_attrs=['p_any_ip_addresses'],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("source_type", "user_setting"),
            match_filters.deep_in("action", USER_SUSPENSION_ACTIONS),
            detection.PythonFilter(suspended_filter)
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - Suspension Enabled",
                    expect_match=True,
                    data=sample_logs.zendesk___suspension_enabled
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Suspension Disabled",
                    expect_match=True,
                    data=sample_logs.zendesk___suspension_disabled
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Admin Role Assigned",
                    expect_match=False,
                    data=sample_logs.zendesk___admin_role_assigned
                ),
                
            ]
        )
    )