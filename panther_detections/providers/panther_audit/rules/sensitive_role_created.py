import typing
from panther_sdk import PantherEvent, detection, schema
from panther_detections.utils import match_filters

from .. import sample_logs

from .._shared import PANTHER_ADMIN_PERMISSIONS, PANTHER_ROLE_ACTIONS

__all__ = ["sensitive_role_created"]


def sensitive_role_created(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A Panther user role has been created that contains admin level permissions."""

    def check_role_create_success() -> detection.PythonFilter:
        def _check_role_create_success(event: PantherEvent) -> bool:
            if event.udm("event_type") not in PANTHER_ROLE_ACTIONS:
                return False
            role_permissions = set(
                event.deep_get("actionParams", "input", "permissions", default="")
            )

            return (
                len(set(PANTHER_ADMIN_PERMISSIONS).intersection(role_permissions)) > 0
                and event.get("actionResult") == "SUCCEEDED"
            )

        return detection.PythonFilter(func=_check_role_create_success)

    def _title(event: PantherEvent) -> str:
        return (
            f"Role with Admin Permissions created by {event.deep_get('actor', 'name')}"
            f"Role Name: {event.deep_get('actionParams', 'input' ,'name')}"
        )

    def _alert_context(event: PantherEvent) -> typing.Dict[str, typing.Any]:
        return {
            "user": event.udm("actor_user"),
            "role_name": event.deep_get("actionParams", "name"),
            "ip": event.udm("source_ip"),
        }

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="A User Role with Sensitive Permissions has been Created",
        rule_id="Panther.Sensitive.Role",
        log_types=[schema.LogTypePantherAudit],
        severity=detection.SeverityHigh,
        description="A Panther user role has been created that contains admin level permissions.",
        tags=["DataModel", "Persistence:Account Manipulation"],
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        runbook="Contact the creator of this role to ensure its creation was appropriate.",
        alert_title=_title,
        summary_attrs=["p_any_ip_addresses"],
        alert_context=_alert_context,
        filters=[check_role_create_success()],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin Role Created",
                    expect_match=True,
                    data=sample_logs.sensitive_role_created_admin_role_created,
                ),
                detection.JSONUnitTest(
                    name="Non-Admin Role Created",
                    expect_match=False,
                    data=sample_logs.sensitive_role_created_non_admin_role_created,
                ),
                detection.JSONUnitTest(
                    name="nonetype error",
                    expect_match=False,
                    data=sample_logs.sensitive_role_created_nonetype_error,
                ),
            ]
        ),
    )
