from panther_sdk import PantherEvent, detection, schema

from .. import sample_logs
from .._shared import rule_tags

# from panther_detections.utils import match_filters


__all__ = ["workspace_gmail_enhanced_predelivery_scanning"]


def workspace_gmail_enhanced_predelivery_scanning(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail."""

    # todo: convert to match_filters
    def _check_scanning_disabled(event: PantherEvent) -> bool:
        # the shape of the items in parameters can change a bit ( like NEW_VALUE can be an array )
        # when the applicationName is something other than admin
        if not event.deep_get("id", "applicationName", default="").lower() == "admin":
            return False
        if all(
            [
                (event.get("name", "") == "CHANGE_APPLICATION_SETTING"),
                (event.deep_get("parameters", "APPLICATION_NAME", default="").lower() == "gmail"),
                (event.deep_get("parameters", "NEW_VALUE", default="").lower() == "true"),
                (
                    event.deep_get("parameters", "SETTING_NAME", default="")
                    == "DelayedDeliverySettingsProto disable_delayed_delivery_for_suspicious_email"
                ),
            ]
        ):
            return True
        return False

    def _title(event: PantherEvent) -> str:
        return (
            f"GSuite Gmail Enhanced Pre-Delivery Scanning was disabled "
            f"for [{event.deep_get('parameters', 'ORG_UNIT_NAME', default='<NO_ORG_UNIT_NAME>')}] "
            f"by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite Workspace Gmail Pre-Delivery Message Scanning Disabled",
        rule_id="GSuite.Workspace.GmailPredeliveryScanningDisabled",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityMedium,
        description="A Workspace Admin Has Disabled Pre-Delivery Scanning For Gmail.",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0001:T1566"]},
        reference="https://support.google.com/a/answer/7380368",
        runbook="Pre-delivery scanning is a feature in Gmail that subjects suspicious emails to additional automated"
        "scrutiny by Google If this change was not intentional, inspect the other actions taken by this actor.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[detection.PythonFilter(func=_check_scanning_disabled)],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Disables Enhanced Pre-Delivery Scanning",
                    expect_match=True,
                    data=sample_logs.workspace_admin_disables_enhanced_pre_delivery_scanning,
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=False,
                    data=sample_logs.admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access,
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.listobject_type,
                ),
            ]
        ),
    )
