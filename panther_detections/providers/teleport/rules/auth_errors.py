import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs


def auth_errors(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A high volume of SSH errors could indicate a brute-force attack"""

    def _title(event: PantherEvent) -> str:
        return f"A high volume of SSH errors was detected from user [{event.get('user', '<UNKNOWN_USER>')}]"

    return detection.Rule(
        overrides=overrides,
        name="Teleport SSH Auth Errors",
        rule_id="Teleport.AuthErrors",
        log_types=[schema.LogTypeGravitationalTeleportAudit],
        severity=detection.SeverityMedium,
        description="A high volume of SSH errors could indicate a brute-force attack",
        tags=["SSH", "Credential Access:Brute Force"],
        reports={"MITRE ATT&CK": ["TA0006:T1110"]},
        reference="https://gravitational.com/teleport/docs/admin-guide/",
        runbook="Check that the user making the failed requests legitimately tried logging in that many times.",
        alert_title=_title,
        summary_attrs=["event", "code", "user", "program", "path", "return_code", "login", "server_id", "sid"],
        threshold=10,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
        filters=(pre_filters or []) + [match_filters.deep_equal("event", "auth"), match_filters.deep_exists("error")],
        unit_tests=(
            [
                detection.JSONUnitTest(name="SSH Errors", expect_match=True, data=sample_logs.ssh_errors),
                detection.JSONUnitTest(name="Echo command", expect_match=False, data=sample_logs.echo_command),
            ]
        ),
    )
