import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def permissions_delegated(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite user was granted new administrator privileges."""
    #from panther_base_helpers import deep_get
    # PERMISSION_DELEGATED_EVENTS = {
    #    "ASSIGN_ROLE",
    # }

    def _title(event: PantherEvent) -> str:
        role = event.deep_get("parameters", "ROLE_NAME")
        user = event.deep_get("parameters", "USER_EMAIL")
        if not role:
            role = "<UNKNOWN_ROLE>"
        if not user:
            user = "<UNKNOWN_USER>"
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}] delegated new"
            f" administrator privileges [{role}] to [{user}]"
        )

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="--DEPRECATED-- GSuite User Delegated Admin Permissions",
        rule_id="GSuite.PermisssionsDelegated",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityLow,
        description="A GSuite user was granted new administrator privileges.",
        tags=['GSuite'],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/admin-delegated-admin-settings#ASSIGN_ROLE",
        runbook="Valdiate that this users should have these permissions and they are not the result of a privilege escalation attack.",
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    if deep_get(event, "id", "applicationName") != "admin":
            #        return False
            #    if event.get("type") == "DELEGATED_ADMIN_SETTINGS":
            #        return bool(event.get("name") in PERMISSION_DELEGATED_EVENTS)
            #    return False

        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Other Admin Action",
                    expect_match=False,
                    data=sample_logs.permissions_delegated_other_admin_action
                ),
                detection.JSONUnitTest(
                    name="Privileges Assigned",
                    expect_match=True,
                    data=sample_logs.permissions_delegated_privileges_assigned
                ),

            ]
        )
    )
