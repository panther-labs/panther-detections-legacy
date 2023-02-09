import typing

from panther_sdk import detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["google_access"]


def google_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Google accessed one of your GSuite resources directly, most likely in response to a support incident."""

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="Google Accessed a GSuite Reource",
        rule_id="GSuite.GoogleAccess",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityLow,
        description="Google accessed one of your GSuite resources directly,"
        "most likely in response to a support incident.",
        tags=rule_tags(),
        # reports=,
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/access-transparency",
        runbook="Your GSuite Super Admin can visit the Access Transparency report"
        "in the GSuite Admin Dashboard to see more details about the access.",
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "access_transparency"),
            match_filters.deep_equal("type", "GSUITE_RESOURCE"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Normal Login Event",
                    expect_match=False,
                    data=sample_logs.google_access_normal_login_event,
                ),
                detection.JSONUnitTest(
                    name="Resource Accessed by Google",
                    expect_match=True,
                    data=sample_logs.google_access_resource_accessed_by_google,
                ),
            ]
        ),
    )
