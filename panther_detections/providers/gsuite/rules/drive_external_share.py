# pylint: disable-all
# WIP rule

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags


def drive_external_share(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """An employee shared a sensitive file externally with another organization"""
    # import datetime
    # from panther_base_helpers import (
    #    PantherUnexpectedAlert,
    #    deep_get,
    #    pattern_match,
    #    pattern_match_list,
    # )
    # COMPANY_DOMAIN = "your-company-name.com"
    # EXCEPTION_PATTERNS = {
    #    # The glob pattern for the document title (lowercased)
    #    "document title p*": {
    #        # All actors allowed to receive the file share
    #        "allowed_for": {
    #            "alice@acme.com",
    #            "samuel@acme.com",
    #            "nathan@acme.com",
    #            "barry@acme.com",
    #            # Allow any user
    #            # "all"
    #            # Allow any user in a specific domain
    #            # "*@acme.com"
    #        },
    #        # The time limit for how long the file share stays valid
    #        "allowed_until": datetime.datetime(year=2030, month=6, day=2),
    #    },
    # }

    # def _title(event: PantherEvent) -> str:
    #    events = event.get("events", [])
    #    actor_email = deep_get(event, "actor", "email", default="EMAIL_UNKNOWN")
    #    matching_events = [
    #        _check_acl_change_event(actor_email, acl_change_event)
    #        for acl_change_event in events
    #        if _check_acl_change_event(actor_email, acl_change_event)
    #    ]
    #    if matching_events:
    #        len_events = len(matching_events)
    #        first_event = matching_events[0]
    #        actor = first_event.get("actor", "ACTOR_UNKNOWN")
    #        doc_title = first_event.get("doc_title", "DOC_TITLE_UNKNOWN")
    #        target_user = first_event.get("target_user", "USER_UNKNOWN")
    #        if len(matching_events) > 1:
    #            return (
    #                f"Multiple dangerous shares ({len_events}) by [{actor}], including "
    #                + f'"{doc_title}" to {target_user}'
    #            )
    #        return f'Dangerous file share by [{actor}]: "{doc_title}" to {target_user}'
    #    raise PantherUnexpectedAlert("No matching events, but DangerousShares still fired")

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        enabled=False,
        name="External GSuite File Share",
        rule_id="GSuite.Drive.ExternalFileShare",
        log_types=schema.LogTypeGSuiteReports,
        severity=detection.SeverityHigh,
        description="An employee shared a sensitive file externally with another organization",
        tags=["GSuite", "Security Control", "Configuration Required", "Collection:Data from Information Repositories"],
        reports={"MITRE ATT&CK": ["TA0009:T1213"]},
        # reference=,
        runbook="Contact the employee who made the share and make sure they redact the access. If the share was legitimate, add to the EXCEPTION_PATTERNS in the detection.",
        alert_title=_title,
        # summary_attrs=,
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            # def rule(event):
            #    application_name = deep_get(event, "id", "applicationName")
            #    events = event.get("events")
            #    actor_email = deep_get(event, "actor", "email", default="EMAIL_UNKNOWN")
            #    if application_name == "drive" and events and "acl_change" in set(e["type"] for e in events):
            #        # If any of the events in this record are a dangerous file share, alert:
            #        return any(
            #            _check_acl_change_event(actor_email, acl_change_event) for acl_change_event in events
            #        )
            #    return False
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Dangerous Share of Known Document with a Missing User",
                    expect_match=True,
                    data=sample_logs.drive_external_share_dangerous_share_of_known_document_with_a_missing_user,
                ),
                detection.JSONUnitTest(
                    name="Dangerous Share of Unknown Document",
                    expect_match=True,
                    data=sample_logs.drive_external_share_dangerous_share_of_unknown_document,
                ),
                detection.JSONUnitTest(
                    name="Share Allowed by Exception",
                    expect_match=False,
                    data=sample_logs.drive_external_share_share_allowed_by_exception,
                ),
            ]
        ),
    )
