import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def create_user_accounts(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has been manually created, modified, or deleted"""
    # from panther_base_helpers import pattern_match_list

    USER_CREATE_PATTERNS = [
        "chage",  # user password expiry
        "passwd",  # change passwords for users
        "user*",  # create, modify, and delete users
    ]

    def _title(event: PantherEvent) -> str:
        return f"User [{event.get('user', '<UNKNOWN_USER>')}] has manually modified system users"

    def _filter(event: PantherEvent) -> bool:
        from fnmatch import fnmatch
        from typing import Sequence

        def pattern_match_list(string_to_match: str, patterns: Sequence[str]):
            """Check that a string matches any pattern in a given list"""
            return any(fnmatch(string_to_match, p) for p in patterns)

        return pattern_match_list(event.get("program"), USER_CREATE_PATTERNS)

    return detection.Rule(
        overrides=overrides,
        name="Teleport Create User Accounts",
        rule_id="Teleport.CreateUserAccounts",
        log_types=["Gravitational.TeleportAudit"],
        severity=detection.SeverityHigh,
        description="A user has been manually created, modified, or deleted",
        tags=["SSH", "Persistence:Create Account"],
        reports={"MITRE ATT&CK": ["TA0003:T1136"]},
        reference="https://gravitational.com/teleport/docs/admin-guide/",
        runbook="Analyze why it was manually created and delete it if necessary.",
        alert_title=_title,
        summary_attrs=["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"],
        alert_grouping=detection.AlertGrouping(period_minutes=15),
        filters=(pre_filters or [])
        + [match_filters.deep_equal("event", "session.command"), detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Echo command", expect_match=False, data=sample_logs.echo_command),
                detection.JSONUnitTest(name="Userdel command", expect_match=True, data=sample_logs.userdel_command),
            ]
        ),
    )
