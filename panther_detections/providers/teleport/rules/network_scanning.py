import typing

from panther_sdk import PantherEvent, detection, schema

from .. import sample_logs


def network_scanning(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has invoked a network scan that could potentially indicate enumeration of the network."""
    SCAN_COMMANDS = ["arp", "arp-scan", "fping", "nmap"]

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{event.get('user', '<UNKNOWN_USER>')}] has issued a network scan with "
            f"[{event.get('program', '<UNKNOWN_PROGRAM>')}]"
        )

    def _filter(event: PantherEvent) -> bool:
        if event.get("event") == "session.command" and not event.get("argv"):
            return False
        # Check that the program is in our watch list
        return event.get("program") in SCAN_COMMANDS

    return detection.Rule(
        overrides=overrides,
        name="Teleport Network Scan Initiated",
        rule_id="Teleport.NetworkScanning",
        log_types=[schema.LogTypeGravitationalTeleportAudit],
        severity=detection.SeverityMedium,
        description="A user has invoked a network scan that could potentially indicate enumeration of the network.",
        tags=["SSH", "Discovery:Network Service Discovery"],
        reports={"MITRE ATT&CK": ["TA0007:T1046"]},
        reference="https://gravitational.com/teleport/docs/admin-guide/",
        runbook="Find related commands within the time window and determine if the command was invoked legitimately. "
        "Examine the arguments to determine how the command was used.",
        alert_title=_title,
        summary_attrs=["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"],
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Echo command", expect_match=False, data=sample_logs.echo_command),
                detection.JSONUnitTest(
                    name="Nmap with no args", expect_match=False, data=sample_logs.nmap_with_no_args
                ),
                detection.JSONUnitTest(name="Nmap with args", expect_match=True, data=sample_logs.nmap_with_args),
                detection.JSONUnitTest(
                    name="Nmap running from crontab", expect_match=True, data=sample_logs.nmap_running_from_crontab
                ),
            ]
        ),
    )
