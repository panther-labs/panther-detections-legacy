import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["google_access"]


def google_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Google accessed one of your GSuite resources directly, most likely in response to a support incident."""
    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get
            if deep_get(event, "id", "applicationName") != "access_transparency":
                return False
            return bool(event.get("type") == "GSUITE_RESOURCE")
        return detection.PythonFilter(func=_rule_filter)

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Google Accessed a GSuite Reource",
        rule_id="GSuite.GoogleAccess",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityLow,
        description="Google accessed one of your GSuite resources directly, most likely in response to a support incident.",
        tags=['GSuite'],
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/access-transparency",
        runbook="Your GSuite Super Admin can visit the Access Transparency report in the GSuite Admin Dashboard to see more details about the access.",
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            rule_filter()
            # match_filters.deep_equal("applicationName", "access_transparency"),
            # match_filters.deep_equal("type", "GSUITE_RESOURCE")
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Login Event",
                    expect_match=False,
                    data=sample_logs.google_access_normal_login_event
                ),
                detection.JSONUnitTest(
                    name="Resource Accessed by Google",
                    expect_match=True,
                    data=sample_logs.google_access_resource_accessed_by_google
                ),

            ]
        )
    )
