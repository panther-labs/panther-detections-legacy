import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    create_alert_context,
)

def admin_policy_updated(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Duo Administrator updated a Policy, which governs how users authenticate."""
        
    def _title(event: PantherEvent) -> str:
        
        return (
            f"Duo: [{event.get('username', '<username_not_found>')}] "
            f"updated [{event.get('object', 'Duo Policy')}]."
        )
    
                
    return detection.Rule(
        overrides=overrides,
        name="Duo Admin Policy Updated",
        rule_id="Duo.Admin.Policy.Updated",
        log_types=['Duo.Administrator'],
        severity=detection.SeverityMedium,
        description="A Duo Administrator updated a Policy, which governs how users authenticate.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("action", "policy_update")
        ],
        alert_title=_title,
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Policy Update",
                    expect_match=True,
                    data=sample_logs.policy_update
                ),
                detection.JSONUnitTest(
                    name="Other event",
                    expect_match=False,
                    data=sample_logs.other_event
                ),
                
            ]
        ),
        alert_context=create_alert_context,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
    )