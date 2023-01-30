import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def suspicious_commands(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has invoked a suspicious command that could lead to a host compromise"""
    SUSPICIOUS_COMMANDS = ["nc", "wget"]

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.get('user', '<UNKNOWN_USER>')}] has executed the command "
            f"[{event.get('program', '<UNKNOWN_PROGRAM>')}]"
        )

    def _filter(event: PantherEvent) -> bool:
        if event.get("event") == "session.command" and not event.get("argv"):
            return False
        # Check that the program is in our watch list
        return event.get("program") in SUSPICIOUS_COMMANDS

    return detection.Rule(
        overrides=overrides,
        name="Teleport Suspicious Commands Executed",
        rule_id="Teleport.SuspiciousCommands",
        log_types=["Gravitational.TeleportAudit"],
        severity=detection.SeverityMedium,
        description="A user has invoked a suspicious command that could lead to a host compromise",
        tags=["SSH", "Execution:Command and Scripting Interpreter"],
        reports={"MITRE ATT&CK": ["TA0002:T1059"]},
        reference="https://gravitational.com/teleport/docs/admin-guide/",
        runbook="Find related commands within the time window and determine if the command was invoked legitimately. Examine the arguments to determine how the command was used and reach out to the user to verify the intentions.",
        alert_title=_title,
        summary_attrs=["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Echo command", expect_match=False, data=sample_logs.echo_command),
                detection.JSONUnitTest(name="Netcat command", expect_match=True, data=sample_logs.netcat_command),
            ]
        ),
    )
