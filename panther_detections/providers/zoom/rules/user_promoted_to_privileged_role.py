import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def user_promoted_to_privileged_role(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Zoom user was promoted to a privileged role."""

    import re

    PRIVILEGED_ROLES = ("Admin", "Co-Owner", "Owner", "Billing Admin")

    def extract_values(event: PantherEvent):
        operator = event.get("operator", "<operator-not-found>")
        operation_detail = event.get("operation_detail", "")
        email = re.search(r"[\w.+-c]+@[\w-]+\.[\w.-]+", operation_detail)[0] or "<email-not-found>"
        fromto = re.findall(r"from ([-\s\w]+) to ([-\s\w]+)", operation_detail) or [
            ("<from-role-not-found>", "<to-role-not-found>")
        ]
        from_role, to_role = fromto[0] or ("<role-not-found>", "<role-not-found>")
        return operator, email, from_role, to_role

    def _title(event: PantherEvent) -> str:
        operator, email, from_role, to_role = extract_values(event)
        return f"Zoom: [{email}]'s role was changed from [{from_role}] " f"to [{to_role}] by [{operator}]."

    def _filter_func(event: PantherEvent) -> bool:
        _, _, from_role, to_role = extract_values(event)
        return to_role in PRIVILEGED_ROLES and from_role not in PRIVILEGED_ROLES

    return detection.Rule(
        overrides=overrides,
        name="Zoom User Promoted to Privileged Role",
        rule_id="Zoom.User.Promoted.to.Privileged.Role",
        log_types=["Zoom.Operation"],
        severity=detection.SeverityMedium,
        description="A Zoom user was promoted to a privileged role.",
        alert_title=_title,
        threshold=1,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal_pattern("action", r"Update"),
            match_filters.deep_equal_pattern("operational_detail", r"^Change Role"),
            match_filters.deep_equal("category_type", "User"),
            detection.PythonFilter(func=_filter_func),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Promotion Event", expect_match=True, data=sample_logs.admin_promotion_event
                ),
                detection.JSONUnitTest(name="Admin to Admin", expect_match=False, data=sample_logs.admin_to_admin),
                detection.JSONUnitTest(
                    name="Admin to Billing Admin", expect_match=False, data=sample_logs.admin_to_billing_admin
                ),
                detection.JSONUnitTest(
                    name="Member to Billing Admin Event",
                    expect_match=True,
                    data=sample_logs.member_to_billing_admin_event,
                ),
                detection.JSONUnitTest(name="Admin to User", expect_match=False, data=sample_logs.admin_to_user),
                detection.JSONUnitTest(name="CoOwner to Admin", expect_match=False, data=sample_logs.coowner_to_admin),
                detection.JSONUnitTest(name="Other Event", expect_match=False, data=sample_logs.other_event),
            ]
        ),
    )
