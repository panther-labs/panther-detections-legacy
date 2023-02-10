from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters, standard_types

from .. import sample_logs
from .._shared import zendesk_get_roles


def user_role(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A user's Zendesk role was changed"""

    def _title(event: PantherEvent) -> str:
        old_role, new_role = zendesk_get_roles(event)
        return (
            f"Actor user [{event.udm('actor_user')}] changed [{event.udm('user')}] role from "
            f"{old_role} to {new_role}"
        )

    def admin_role_filter(event: PantherEvent) -> bool:
        # admin roles have their own handling
        if event.udm("event_type") != standard_types.ADMIN_ROLE_ASSIGNED:
            _, new_role = zendesk_get_roles(event)
            return bool(new_role)
        return False

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Zendesk User Role Changed",
        rule_id="Zendesk.UserRoleChanged",
        log_types=["Zendesk.Audit"],
        severity=detection.SeverityInfo,
        description="A user's Zendesk role was changed",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=[
            match_filters.deep_equal("source_type", "user"),
            match_filters.deep_equal("action", "update"),
            detection.PythonFilter(func=admin_role_filter),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Zendesk - Role Changed", expect_match=True, data=sample_logs.zendesk___role_changed
                ),
                detection.JSONUnitTest(
                    name="Zendesk - Admin Role Assigned",
                    expect_match=False,
                    data=sample_logs.zendesk___admin_role_assigned,
                ),
            ]
        ),
    )
