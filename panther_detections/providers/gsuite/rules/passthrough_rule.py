import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    ACTIVITY_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def passthrough_rule(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite rule was triggered."""
        
    def _title(event: PantherEvent) -> str:
        rule_severity = event.deep_get("parameters", "severity")
        if event.deep_get(event, "parameters", "rule_name"):
            return (
                "GSuite "
                + rule_severity
                + " Severity Rule Triggered: "
                + event.deep_get(event, "parameters", "rule_name")
            )

        return f"GSuite {rule_severity} Severity Rule Triggered"
    
    def _severity(event: PantherEvent) -> str:
        return event.deep_get("parameters", "severity", default="INFO")
    
                
    return detection.Rule(
        overrides=overrides,
        name="GSuite Passthrough Rule Triggered",
        rule_id="GSuite.Rule",
        log_types=[ACTIVITY_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=_severity,
        description="A GSuite rule was triggered.",
        reference="https://support.google.com/a/answer/9420866",
        runbook="Investigate what triggered the rule.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "rules"),
            match_filters.deep_exists("parameters.triggered_actions")
        ],
        alert_title=_title,
        alert_context="",
        summary_attrs=
            ['actor:email']
        ,
        threshold="",
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Non Triggered Rule",
                    expect_match=False,
                    data=sample_logs.non_triggered_rule
                ),
                detection.JSONUnitTest(
                    name="High Severity Rule",
                    expect_match=True,
                    data=sample_logs.high_severity_rule
                ),
                detection.JSONUnitTest(
                    name="Medium Severity Rule",
                    expect_match=True,
                    data=sample_logs.medium_severity_rule
                ),
                detection.JSONUnitTest(
                    name="Low Severity Rule",
                    expect_match=True,
                    data=sample_logs.low_severity_rule
                ),
                detection.JSONUnitTest(
                    name="High Severity Rule with Rule Name",
                    expect_match=True,
                    data=sample_logs.high_severity_rule_with_rule_name
                ),
                
            ]
        )
    )