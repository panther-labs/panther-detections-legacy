import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )


def drive_overly_visible(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google drive resource that is overly visible has been modified."""
    # from panther_base_helpers import deep_get
    # from panther_base_helpers import gsuite_details_lookup as details_lookup
    # from panther_base_helpers import gsuite_parameter_lookup as param_lookup
    # RESOURCE_CHANGE_EVENTS = {
    #    "create",
    #    "move",
    #    "upload",
    #    "edit",
    # }
    # PERMISSIVE_VISIBILITY = {
    #    "people_with_link",
    #    "public_on_the_web",
    # }

    # def _title(event: PantherEvent) -> str:
    #    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
    #    doc_title = param_lookup(details.get("parameters", {}), "doc_title")
    #    share_settings = param_lookup(details.get("parameters", {}), "visibility")
    #    return (
    #        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_EMAIL>')}]"
    #        f" modified a document [{doc_title}] that has overly permissive share"
    #        f" settings [{share_settings}]"
    #    )

    # def _group_by(event: PantherEvent) -> str:
    #    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
    #    if param_lookup(details.get("parameters", {}), "doc_title"):
    #        return param_lookup(details.get("parameters", {}), "doc_title")
    #    return "<UNKNOWN_DOC_TITLE>"

    return detection.Rule(
        overrides=overrides,
        # enabled=,
        name="GSuite Overly Visible Drive Document",
        rule_id="GSuite.DriveOverlyVisible",
        log_types=["GSuite.Reports"],
        severity=detection.SeverityInfo,
        description="A Google drive resource that is overly visible has been modified.",
        tags=["GSuite", "Collection:Data from Information Repositories"],
        reports={"MITRE ATT&CK": ["TA0009:T1213"]},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive#access",
        runbook="Investigate whether the drive document is appropriate to be this visible.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        alert_grouping=detection.AlertGrouping(group_by=_group_by, period_minutes=15),
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    if deep_get(event, "id", "applicationName") != "drive":
            #        return False
            #    details = details_lookup("access", RESOURCE_CHANGE_EVENTS, event)
            #    return (
            #        bool(details)
            #        and param_lookup(details.get("parameters", {}), "visibility") in PERMISSIVE_VISIBILITY
            #    )
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Access Event", expect_match=False, data=sample_logs.drive_overly_visible_access_event
                ),
                detection.JSONUnitTest(
                    name="Modify Event Without Over Visibility",
                    expect_match=False,
                    data=sample_logs.drive_overly_visible_modify_event_without_over_visibility,
                ),
                detection.JSONUnitTest(
                    name="Overly Visible Doc Modified",
                    expect_match=True,
                    data=sample_logs.drive_overly_visible_overly_visible_doc_modified,
                ),
            ]
        ),
    )
