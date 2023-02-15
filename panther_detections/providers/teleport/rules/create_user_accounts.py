from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import USER_CREATE_PATTERNS, rule_tags


def create_user_accounts(
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
) -> detection.Rule:
    """A user has been manually created, modified, or deleted"""

    def _title(event: PantherEvent) -> str:
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] has manually modified system users"

    def _filter_pattern_match(event: PantherEvent) -> bool:
        from panther_detections.utils.legacy_utils import pattern_match_list

        return pattern_match_list(event.get("program"), USER_CREATE_PATTERNS)

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        name="Teleport Create User Accounts",
        rule_id="Teleport.CreateUserAccounts",
        log_types=[schema.LogTypeGravitationalTeleportAudit],
        severity=detection.SeverityHigh,
        description="A user has been manually created, modified, or deleted",
        tags=rule_tags("SSH", "Persistence:Create Account"),
        reports={"MITRE ATT&CK": ["TA0003:T1136"]},
        reference="https://gravitational.com/teleport/docs/admin-guide/",
        runbook="Analyze why it was manually created and delete it if necessary.",
        alert_title=_title,
        summary_attrs=["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"],
        alert_grouping=detection.AlertGrouping(period_minutes=15),
        filters=[
            match_filters.deep_equal("event", "session.command"),
            detection.PythonFilter(func=_filter_pattern_match),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Echo command", expect_match=False, data=sample_logs.echo_command),
                detection.JSONUnitTest(name="Userdel command", expect_match=True, data=sample_logs.userdel_command),
            ]
        ),
    )
