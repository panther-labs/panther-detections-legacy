import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     SYSTEM_LOG_TYPE,
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def duo_admin_new_admin_api_app_integration(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """Identifies creation of new Admin API integrations for Duo."""

    # def _title(event: PantherEvent) -> str:
    #
    #     return "The title of the alert"

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin New Admin API App Integration",
        rule_id="Duo.Admin.New.Admin.API.App.Integration",
        log_types=["Duo.Administrator"],
        # tags=(overrides.tags),
        # reports="",
        severity=detection.SeverityHigh,
        description="Identifies creation of new Admin API integrations for Duo.",
        # reference="",
        # runbook="",
        filters=(pre_filters or [])
        + [
            # filters
        ],
        alert_title=_title,
        # summary_attrs=(overrides.summary_attrs),
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Admin API Integration Created",
                    expect_match=True,
                    data=sample_logs.admin_api_integration_created,
                ),
                detection.JSONUnitTest(
                    name="Non Admin API Integration", expect_match=False, data=sample_logs.non_admin_api_integration
                ),
                detection.JSONUnitTest(name="Other Event", expect_match=False, data=sample_logs.other_event),
            ]
        ),
        # alert_context=,
        # alert_grouping=
        # destinations=
        # enabled=
    )
