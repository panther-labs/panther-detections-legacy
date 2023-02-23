from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs


def drive_overly_visible(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google drive resource that is overly visible has been modified."""

    resource_change_events = {
        "create",
        "move",
        "upload",
        "edit",
    }
    permissive_visibility = {
        "people_with_link",
        "public_on_the_web",
    }

    def details_in_params() -> detection.PythonFilter:
        def _details_in_params(evt: PantherEvent) -> bool:
            from panther_detections.providers.gsuite._shared import (
                gsuite_details_lookup,
                gsuite_parameter_lookup,
            )

            details = gsuite_details_lookup("access", resource_change_events, evt)
            return (
                bool(details)
                and gsuite_parameter_lookup(details.get("parameters", {}), "visibility") in permissive_visibility
            )

        return detection.PythonFilter(func=_details_in_params)

    def _title(event: PantherEvent) -> str:
        from panther_detections.providers.gsuite._shared import (
            gsuite_details_lookup,
            gsuite_parameter_lookup,
        )

        details = gsuite_details_lookup("access", resource_change_events, event)
        doc_title = gsuite_parameter_lookup(details.get("parameters", {}), "doc_title")
        share_settings = gsuite_parameter_lookup(details.get("parameters", {}), "visibility")
        return (
            f"User [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
            f" modified a document [{doc_title}] that has overly permissive share"
            f" settings [{share_settings}]"
        )

    def _group_by(event: PantherEvent) -> str:
        from panther_detections.providers.gsuite._shared import (
            gsuite_details_lookup,
            gsuite_parameter_lookup,
        )

        details = gsuite_details_lookup("access", resource_change_events, event)
        if gsuite_parameter_lookup(details.get("parameters", {}), "doc_title"):
            return gsuite_parameter_lookup(details.get("parameters", {}), "doc_title")
        return "<UNKNOWN_DOC_TITLE>"

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite Overly Visible Drive Document",
        rule_id="GSuite.DriveOverlyVisible",
        log_types=schema.LogTypeGSuiteReports,
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
        filters=[
            match_filters.deep_equal("id.applicationName", "drive"),
            details_in_params(),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Access Event",
                    expect_match=False,
                    data=sample_logs.drive_overly_visible_access_event,
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
