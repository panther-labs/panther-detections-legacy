import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import PANTHER_USER_ACTIONS

__all__ = ["user_modified"]


def user_modified(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Panther user's role has been modified. This could mean password, email, or role has changed for the user."""

    def _title(event: PantherEvent) -> str:
        return (
            f"The user account "
            f"{event.deep_get('actionParams', 'dynamic', 'input', 'email', default='<UNKNOWN_USER>')}"
            #    f" was modified by {event.udm('actor_user')}"
            f" was modified by {event.deep_get('actor', 'name')}"
        )

    def _alert_context(event: PantherEvent) -> typing.Dict[str, typing.Any]:
        return {
            #    "user": event.udm("actor_user"),
            "user": event.deep_get("actor", "name"),
            "change_target": event.deep_get("actionParams", "dynamic", "input", "email", default="<UNKNOWN_USER>"),
            #    "ip": event.udm("source_ip"),
            "ip": event.get("source_IP"),
        }

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="A User's Panther Account was Modified",
        rule_id="Panther.User.Modified",
        log_types=[schema.LogTypePantherAudit],
        severity=detection.SeverityHigh,
        description="A Panther user's role has been modified. This could mean password, email,"
        " or role has changed for the user.",
        tags=["DataModel", "Persistence:Account Manipulation"],
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        # reference=,
        runbook="Validate that this user modification was intentional.",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        # threshold=,
        alert_context=_alert_context,
        # alert_grouping=,
        filters=[
            match_filters.deep_in("actionName", PANTHER_USER_ACTIONS),
            match_filters.deep_equal("actionResult", "SUCCEEDED"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Role Created",
                    expect_match=False,
                    data=sample_logs.user_modified_admin_role_created,
                ),
                detection.JSONUnitTest(
                    name="Users's email was changed",
                    expect_match=True,
                    data=sample_logs.user_modified_users_email_was_changed,
                ),
                detection.JSONUnitTest(
                    name="Users's role was changed",
                    expect_match=True,
                    data=sample_logs.user_modified_users_role_was_changed,
                ),
            ]
        ),
    )
