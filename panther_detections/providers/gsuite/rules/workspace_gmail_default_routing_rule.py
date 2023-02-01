import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["workspace_gmail_default_routing_rule"]


def workspace_gmail_default_routing_rule(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A Workspace Admin Has Modified A Default Routing Rule In Gmail"""
    #from panther_base_helpers import deep_get

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get
            if all(
                    [
                        (event.get("type", "") == "EMAIL_SETTINGS"),
                        (event.get("name", "").endswith("_GMAIL_SETTING")),
                        (deep_get(event, "parameters", "SETTING_NAME",
                                  default="") == "MESSAGE_SECURITY_RULE"),
                    ]):
                return True
            return False
        return detection.PythonFilter(func=_rule_filter)

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
        # enabled=,
        name="GSuite Workspace Gmail Default Routing Rule Modified",
        rule_id="GSuite.Workspace.GmailDefaultRoutingRuleModified",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityHigh,
        description="A Workspace Admin Has Modified A Default Routing Rule In Gmail",
        tags=['GSuite'],
        reports={'MITRE ATT&CK': ['TA0003:T1098']},
        reference="https://support.google.com/a/answer/2368153?hl=en",
        runbook="Administrators use Default Routing to set up how inbound email is delivered within an organization. The configuration of the default routing rule needs to be inspected in order to verify the intent of the rule is benign. If this change was not planned, inspect the other actions taken by this actor.",
        alert_title=_title,
        summary_attrs=['actor:email'],
        # threshold=,
        # alert_context=,
        # alert_grouping=,
        filters=(pre_filters or [])
        + [
            rule_filter()
        ],
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Workspace Admin Creates Default Routing Rule",
                    expect_match=True,
                    data=sample_logs.workspace_gmail_default_routing_rule_workspace_admin_creates_default_routing_rule
                ),
                detection.JSONUnitTest(
                    name="Workspace Admin Deletes Default Routing Rule",
                    expect_match=True,
                    data=sample_logs.workspace_gmail_default_routing_rule_workspace_admin_deletes_default_routing_rule
                ),
                detection.JSONUnitTest(
                    name="Admin Set Default Calendar SHARING_OUTSIDE_DOMAIN Setting to READ_ONLY_ACCESS",
                    expect_match=False,
                    data=sample_logs.workspace_gmail_default_routing_rule_admin_set_default_calendar_sharing_outside_domain_setting_to_read_only_access
                ),
                detection.JSONUnitTest(
                    name="ListObject Type",
                    expect_match=False,
                    data=sample_logs.workspace_gmail_default_routing_rule_listobject_type
                ),

            ]
        )
    )
