import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import get_zoom_user_context


def operation_user_granted_admin_deprecated(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Zoom user has been granted admin access"""

    def _title(event: PantherEvent) -> str:
        context = get_zoom_user_context(event)
        return f"Zoom User {context['User']} was made an admin by {event.get('operator')}"

    def _filter_func(event: PantherEvent) -> bool:
        context = get_zoom_user_context(event)
        return "Member to Admin" in context["Change"]

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="--DEPRECATED -- Zoom User Granted Admin Rights",
        rule_id="Zoom.UserGrantedAdmin",
        log_types=["Zoom.Operation"],
        severity=detection.SeverityMedium,
        description="A Zoom user has been granted admin access",
        tags=["Zoom", "Privilege Escalation:Valid Accounts"],
        reports={"MITRE ATT&CK": ["TA0004:T1078"]},
        reference="https://support.zoom.us/hc/en-us/articles/115001078646-Using-role-management",
        runbook="Contact Zoom admin and ensure this access level is intended and appropriate",
        alert_title=_title,
        summary_attrs=["p_any_emails"],
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("Action", "Update"),
            match_filters.deep_equal("category_type", "User"),
            detection.PythonFilter(func=_filter_func),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="User Granted Admin", expect_match=True, data=sample_logs.user_granted_admin
                ),
                detection.JSONUnitTest(
                    name="Non-admin user update", expect_match=False, data=sample_logs.non_admin_user_update
                ),
            ]
        ),
    )
