import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def google_access(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Google accessed one of your GSuite resources directly, most likely in response to a support incident."""
    #from panther_base_helpers import deep_get

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
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    if deep_get(event, "id", "applicationName") != "access_transparency":
            #        return False
            #    return bool(event.get("type") == "GSUITE_RESOURCE")

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
