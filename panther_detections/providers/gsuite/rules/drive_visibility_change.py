# pylint: disable-all
# WIP rule

import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags


def drive_visibility_change(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Google drive resource became externally accessible."""
    # import json
    # from unittest.mock import MagicMock
    # from panther_base_helpers import deep_get
    # from panther_base_helpers import gsuite_parameter_lookup as param_lookup
    # Add any domain name(s) that you expect to share documents with in the ALLOWED_DOMAINS set
    # ALLOWED_DOMAINS = set()
    # PUBLIC_PROVIDERS = {
    #    "gmail.com",
    #    "yahoo.com",
    #    "outlook.com",
    #    "aol.com",
    #    "yandex.com",
    #    "protonmail.com",
    #    "pm.me",
    #    "icloud.com",
    #    "tutamail.com",
    #    "tuta.io",
    #    "keemail.me",
    #    "mail.com",
    #    "zohomail.com",
    #    "hotmail.com",
    #    "msn.com",
    # }
    # VISIBILITY = {
    #    "people_with_link",
    #    "people_within_domain_with_link",
    #    "public_on_the_web",
    #    "shared_externally",
    #    "unknown",
    # }
    # ALERT_DETAILS = {}
    # Events where documents have changed perms due to parent folder change
    # INHERITANCE_EVENTS = {
    #    "change_user_access_hierarchy_reconciled",
    #    "change_document_access_scope_hierarchy_reconciled",
    # }

    # def _title(event: PantherEvent) -> str:
    #    log = event.get("p_row_id")
    #    if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
    #        if len(ALERT_DETAILS[log]["TARGET_USER_EMAILS"]) == 1:
    #            sharing_scope = ALERT_DETAILS[log]["TARGET_USER_EMAILS"][0]
    #        else:
    #            sharing_scope = "multiple users"
    #        if ALERT_DETAILS[log]["NEW_VISIBILITY"] == "shared_externally":
    #            sharing_scope += " (outside the document's current domain)"
    #    elif ALERT_DETAILS[log]["TARGET_DOMAIN"] == "all":
    #        sharing_scope = "the entire internet"
    #        if ALERT_DETAILS[log]["NEW_VISIBILITY"] == "people_with_link":
    #            sharing_scope += " (anyone with the link)"
    #        elif ALERT_DETAILS[log]["NEW_VISIBILITY"] == "public_on_the_web":
    #            sharing_scope += " (link not required)"
    #    else:
    #        sharing_scope = f"the {ALERT_DETAILS[log]['TARGET_DOMAIN']} domain"
    #        if ALERT_DETAILS[log]["NEW_VISIBILITY"] == "people_within_domain_with_link":
    #            sharing_scope += f" (anyone in {ALERT_DETAILS[log]['TARGET_DOMAIN']} with the link)"
    #        elif ALERT_DETAILS[log]["NEW_VISIBILITY"] == "public_in_the_domain":
    #            sharing_scope += f" (anyone in {ALERT_DETAILS[log]['TARGET_DOMAIN']})"
    #    alert_access_scope = ALERT_DETAILS[log]["ACCESS_SCOPE"][0].replace("can_", "")
    #    return (
    #        f"User [{deep_get(event, 'actor', 'email', default='<UNKNOWN_USER>')}] made the document "
    #        f"[{ALERT_DETAILS[log]['DOC_TITLE']}] externally visible to [{sharing_scope}] with "
    #        f"[{alert_access_scope}] access"
    #    )

    # def _severity(event: PantherEvent) -> str:
    #    log = event.get("p_row_id")
    #    if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
    #        for address in ALERT_DETAILS[log]["TARGET_USER_EMAILS"]:
    #            domain = address.split("@")[1]
    #            if domain in PUBLIC_PROVIDERS:
    #                return "LOW"
    #    return "INFO"

    # def _group_by(event: PantherEvent) -> str:
    #    log = event.get("p_row_id")
    #    return ALERT_DETAILS[log]["DOC_TITLE"]

    # def _alert_context(event: PantherEvent) -> Dict[str, Any]:
    #    log = event.get("p_row_id")
    #    if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
    #        return {"target users": ALERT_DETAILS[log]["TARGET_USER_EMAILS"]}
    #    return {}

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="GSuite External Drive Document",
        rule_id="GSuite.DriveVisibilityChanged",
        log_types=schema.LogTypeGSuiteReports,
        severity=detection.DynamicStringField(func=_severity, fallback=detection.SeverityLow),
        description="A Google drive resource became externally accessible.",
        tags=["GSuite", "Collection:Data from Information Repositories", "Configuration Required"],
        reports={"MITRE ATT&CK": ["TA0009:T1213"]},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/drive#acl_change",
        runbook="Investigate whether the drive document is appropriate to be publicly accessible.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        alert_context=_alert_context,
        alert_grouping=detection.AlertGrouping(group_by=_group_by, period_minutes=15),
        filters=(pre_filters or [])
        + [
            # def rule(event):
            #    # pylint: disable=too-complex
            #    global ALLOWED_DOMAINS  # pylint: disable=global-statement
            #    if deep_get(event, "id", "applicationName") != "drive":
            #        return False
            #    # Events that have the types in INHERITANCE_EVENTS are
            #    # changes to documents and folders that occur due to
            #    # a change in the parent folder's permission. We ignore
            #    # these events to prevent every folder change from
            #    # generating multiple alerts.
            #    if deep_get(event, "events", "name") in INHERITANCE_EVENTS:
            #        return False
            #    log = event.get("p_row_id")
            #    init_alert_details(log)
            #    #########
            #    # for visibility changes that apply to a domain, not a user
            #    change_document_visibility = False
            #    # We need to type-cast ALLOWED_DOMAINS for unit testing mocks
            #    if isinstance(ALLOWED_DOMAINS, MagicMock):
            #        ALLOWED_DOMAINS = set(json.loads(ALLOWED_DOMAINS()))  # pylint: disable=not-callable
            #    for details in event.get("events", [{}]):
            #        if (
            #            details.get("type") == "acl_change"
            #            and details.get("name") == "change_document_visibility"
            #            and param_lookup(details.get("parameters", {}), "new_value") != ["private"]
            #            and not param_lookup(details.get("parameters", {}), "target_domain") in ALLOWED_DOMAINS
            #            and param_lookup(details.get("parameters", {}), "visibility") in VISIBILITY
            #        ):
            #            ALERT_DETAILS[log]["TARGET_DOMAIN"] = param_lookup(
            #                details.get("parameters", {}), "target_domain"
            #            )
            #            ALERT_DETAILS[log]["NEW_VISIBILITY"] = param_lookup(
            #                details.get("parameters", {}), "visibility"
            #            )
            #            ALERT_DETAILS[log]["DOC_TITLE"] = param_lookup(
            #                details.get("parameters", {}), "doc_title"
            #            )
            #            change_document_visibility = True
            #            break
            #    # "change_document_visibility" events are always paired with
            #    # "change_document_access_scope" events. the "target_domain" and
            #    # "visibility" attributes are equivalent.
            #    if change_document_visibility:
            #        for details in event.get("events", [{}]):
            #            if (
            #                details.get("type") == "acl_change"
            #                and details.get("name") == "change_document_access_scope"
            #                and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
            #            ):
            #                ALERT_DETAILS[log]["ACCESS_SCOPE"] = param_lookup(
            #                    details.get("parameters", {}), "new_value"
            #                )
            #        return True
            #    #########
            #    # for visibility changes that apply to a user
            #    # there is a change_user_access event for each user
            #    # change_user_access and change_document_visibility events are
            #    # not found in the same report
            #    change_user_access = False
            #    for details in event.get("events", [{}]):
            #        if (
            #            details.get("type") == "acl_change"
            #            and details.get("name") == "change_user_access"
            #            and param_lookup(details.get("parameters", {}), "new_value") != ["none"]
            #            and user_is_external(param_lookup(details.get("parameters", {}), "target_user"))
            #        ):
            #            if ALERT_DETAILS[log]["TARGET_USER_EMAILS"] != ["<UNKNOWN_USER>"]:
            #                ALERT_DETAILS[log]["TARGET_USER_EMAILS"].append(
            #                    param_lookup(details.get("parameters", {}), "target_user")
            #                )
            #            else:
            #                ALERT_DETAILS[log]["TARGET_USER_EMAILS"] = [
            #                    param_lookup(details.get("parameters", {}), "target_user")
            #                ]
            #                ALERT_DETAILS[log]["DOC_TITLE"] = param_lookup(
            #                    details.get("parameters", {}), "doc_title"
            #                )
            #                ALERT_DETAILS[log]["ACCESS_SCOPE"] = param_lookup(
            #                    details.get("parameters", {}), "new_value"
            #                )
            #            change_user_access = True
            #    return change_user_access
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Access Event", expect_match=False, data=sample_logs.drive_visibility_change_access_event
                ),
                detection.JSONUnitTest(
                    name="ACL Change without Visibility Change",
                    expect_match=False,
                    data=sample_logs.drive_visibility_change_acl_change_without_visibility_change,
                ),
                detection.JSONUnitTest(
                    name="Doc Became Public - Link (Unrestricted)",
                    expect_match=True,
                    data=sample_logs.drive_visibility_change_doc_became_public___link_(unrestricted),
                ),
                detection.JSONUnitTest(
                    name="Doc Became Public - Link (Allowlisted Domain Not Configured)",
                    expect_match=True,
                    data=sample_logs.drive_visibility_change_doc_became_public___link_(
                        allowlisted_domain_not_configured
                    ),
                ),
                detection.JSONUnitTest(
                    name="Doc Became Public - Link (Allowlisted Domain Is Configured)",
                    expect_match=False,
                    data=sample_logs.drive_visibility_change_doc_became_public___link_(
                        allowlisted_domain_is_configured
                    ),
                ),
                detection.JSONUnitTest(
                    name="Doc Became Private - Link",
                    expect_match=False,
                    data=sample_logs.drive_visibility_change_doc_became_private___link,
                ),
                detection.JSONUnitTest(
                    name="Doc Became Public - User",
                    expect_match=True,
                    data=sample_logs.drive_visibility_change_doc_became_public___user,
                ),
                detection.JSONUnitTest(
                    name="Doc Became Public - User (Multiple)",
                    expect_match=True,
                    data=sample_logs.drive_visibility_change_doc_became_public___user_(multiple),
                ),
                detection.JSONUnitTest(
                    name="Doc Inherits Folder Permissions",
                    expect_match=False,
                    data=sample_logs.drive_visibility_change_doc_inherits_folder_permissions,
                ),
                detection.JSONUnitTest(
                    name="Doc Inherits Folder Permissions - Sharing Link",
                    expect_match=False,
                    data=sample_logs.drive_visibility_change_doc_inherits_folder_permissions___sharing_link,
                ),
                detection.JSONUnitTest(
                    name="Doc Became Public - Public email provider",
                    expect_match=True,
                    data=sample_logs.drive_visibility_change_doc_became_public___public_email_provider,
                ),
                detection.JSONUnitTest(
                    name="Doc Shared With Multiple Users All From ALLOWED_DOMAINS",
                    expect_match=False,
                    data=sample_logs.drive_visibility_change_doc_shared_with_multiple_users_all_from_allowed_domains,
                ),
            ]
        ),
    )
