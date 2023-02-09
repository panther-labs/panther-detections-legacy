import typing

from panther_sdk import PantherEvent, detection, schema

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["passthrough_rule"]


def passthrough_rule(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A GSuite rule was triggered."""

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get

            if deep_get(event, "id", "applicationName") != "rules":
                return False
            if not deep_get(event, "parameters", "triggered_actions"):
                return False
            return True

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        rule_severity = event.deep_get("parameters", "severity")
        if event.deep_get("parameters", "rule_name"):
            return "GSuite " + rule_severity + " Severity Rule Triggered: " + event.deep_get("parameters", "rule_name")
        return "GSuite " + rule_severity + " Severity Rule Triggered"

    def _severity(event: PantherEvent) -> str:
        return event.deep_get("parameters", "severity", default="INFO")

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Passthrough Rule Triggered",
        rule_id="GSuite.Rule",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityInfo),
        description="A GSuite rule was triggered.",
        tags=rule_tags(),
        # reports=,
        reference="https://support.google.com/a/answer/9420866",
        runbook="Investigate what triggered the rule.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            # match_filters.deep_equal("applicationName", "rules"),
            # match_filters.deep_exists("triggered_actions")
            rule_filter()
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Non Triggered Rule", expect_match=False, data=sample_logs.passthrough_rule_non_triggered_rule
                ),
                detection.JSONUnitTest(
                    name="High Severity Rule", expect_match=True, data=sample_logs.passthrough_rule_high_severity_rule
                ),
                detection.JSONUnitTest(
                    name="Medium Severity Rule",
                    expect_match=True,
                    data=sample_logs.passthrough_rule_medium_severity_rule,
                ),
                detection.JSONUnitTest(
                    name="Low Severity Rule", expect_match=True, data=sample_logs.passthrough_rule_low_severity_rule
                ),
                detection.JSONUnitTest(
                    name="High Severity Rule with Rule Name",
                    expect_match=True,
                    data=sample_logs.passthrough_rule_high_severity_rule_with_rule_name,
                ),
            ]
        ),
    )
