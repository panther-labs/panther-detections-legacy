import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs

def scheduled_jobs(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has manually edited the Linux crontab"""
    
    def _title(event: PantherEvent) -> str:
       return f"User [{event.get('user', '<UNKNOWN_USER>')}] has modified scheduled jobs"

    def _filter(event: PantherEvent) -> bool:
        if "-l" in event.get("argv", []):
            return False
        return True


    return detection.Rule(
        overrides=overrides,
        name="Teleport Scheduled Jobs",
        rule_id="Teleport.ScheduledJobs",
        log_types=['Gravitational.TeleportAudit'],
        severity=detection.SeverityMedium,
        description="A user has manually edited the Linux crontab",
        tags=['SSH', 'Execution:Scheduled Task/Job'],
        reports={'MITRE ATT&CK': ['TA0002:T1053']},
        reference="https://gravitational.com/teleport/docs/admin-guide/",
        runbook="Validate the user behavior and rotate the host if necessary.",
        alert_title=_title,
        summary_attrs=['event', 'code', 'user', 'program', 'path', 'return_code', 'login', 'server_id', 'sid'],
        threshold=10,
        alert_grouping=detection.AlertGrouping(period_minutes=15),
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("event", "session.command"),
            match_filters.deep_equal("program", "crontab"),
            detection.PythonFilter(func=_filter)
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Crontab no args",
                    expect_match=True,
                    data=sample_logs.crontab_no_args
                ),
                detection.JSONUnitTest(
                    name="Crontab Edit",
                    expect_match=True,
                    data=sample_logs.crontab_edit
                ),
                detection.JSONUnitTest(
                    name="Crontab List",
                    expect_match=False,
                    data=sample_logs.crontab_list
                ),
                detection.JSONUnitTest(
                    name="Echo command",
                    expect_match=False,
                    data=sample_logs.echo_command
                ),
                
            ]
        )
    )