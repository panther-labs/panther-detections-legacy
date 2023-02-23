from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .. import sample_logs
from .._shared import rule_tags

__all__ = ["workspace_gmail_default_routing_rule"]


def workspace_gmail_default_routing_rule(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Modified A Default Routing Rule In Gmail"""

    def _title(event: PantherEvent) -> str:
        # Gmail records the event name as DELETE_GMAIL_SETTING/CREATE_GMAIL_SETTING
        # We shouldn't be able to enter title() unless event[name] ends with
        #  _GMAIL_SETTING, and as such change_type assumes the happy path.
        change_type = f"{event.get('name', '').split('_')[0].lower()}d"
        return (
            f"GSuite Gmail Default Routing Rule Was "
            f"[{change_type}] "
            f"by [{event.deep_get('actor', 'email', default='<UNKNOWN_EMAIL>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        # enabled=,
        name="GSuite Workspace Gmail Default Routing Rule Modified",
        rule_id="GSuite.Workspace.GmailDefaultRoutingRuleModified",
        log_types=schema.LogTypeGSuiteActivityEvent,
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Modified A Default Routing Rule In Gmail",
        tags=rule_tags(),
        reports={"MITRE ATT&CK": ["TA0003:T1098"]},
        reference="https://support.google.com/a/answer/2368153?hl=en",
        runbook="Administrators use Default Routing to set up how inbound email is delivered within an organization."
        "The configuration of the default routing rule needs to be inspected in order to"
        "verify the intent of the rule is benign. If this change was not planned"
        "inspect the other actions taken by this actor.",
        alert_title=_title,
        summary_attrs=["actor:email"],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=[
            match_filters.deep_equal("type", "EMAIL_SETTINGS"),
            match_filters.deep_ends_with("name", "_GMAIL_SETTING"),
            match_filters.deep_equal("parameters.SETTING_NAME", "MESSAGE_SECURITY_RULE"),
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Creates Default Routing Rule",
                    expect_match=True,
                    data=sample_logs.workspace_admin_creates_default_routing_rule,
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Deletes Default Routing Rule",
                    expect_match=True,
                    data=sample_logs.workspace_admin_deletes_default_routing_rule,
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
