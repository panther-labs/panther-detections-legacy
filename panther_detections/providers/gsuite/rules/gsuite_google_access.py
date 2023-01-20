import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import (
    SYSTEM_LOG_TYPE,
    rule_tags,
    standard_tags,
)

def gsuite_google_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Google accessed one of your GSuite resources directly, most likely in response to a support incident."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert"" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Google Accessed a GSuite Reource",
        rule_id="GSuite.GoogleAccess",
        log_types=[SYSTEM_LOG_TYPE],
        tags=rule_tags(
            ['GSuite'],
        ),
        reports="",
        severity=detection.SeverityLow,
        description="Google accessed one of your GSuite resources directly, most likely in response to a support incident.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/access-transparency",
        runbook="Your GSuite Super Admin can visit the Access Transparency report in the GSuite Admin Dashboard to see more details about the access.",
        filters=(pre_filters or [])
        + [
            #filters
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
                    name="Normal Login Event",
                    expect_match=False,
                    data=sample_logs.normal_login_event
                ),
                detection.JSONUnitTest(
                    name="Resource Accessed by Google",
                    expect_match=True,
                    data=sample_logs.resource_accessed_by_google
                ),
                
            ]
        )
    )