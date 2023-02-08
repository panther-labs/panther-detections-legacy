import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags, slack_alert_context

__all__ = ["org_created"]
__all__ = ["org_created"]


def org_created(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Detects when a Slack organization is created"""

    return detection.Rule(
        overrides=overrides,
        name="Slack Organization Created",
        rule_id="Slack.AuditLogs.OrgCreated",
        log_types=[schema.LogTypeSlackAuditLogs],
        severity=detection.SeverityLow,
        description="Detects when a Slack organization is created",
        tags=rule_tags(),
        reference="https://api.slack.com/admins/audit-logs",
        summary_attrs=["p_any_ip_addresses", "p_any_emails"],
        threshold=1,
        alert_context=slack_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "organization_created")],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Organization Created", expect_match=True, data=sample_logs.org_created_organization_created
                ),
                detection.JSONUnitTest(
                    name="Organization Deleted", expect_match=False, data=sample_logs.org_created_organization_deleted
                ),
            ]
        ),
    )
