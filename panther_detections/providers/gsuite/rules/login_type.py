import typing
from panther_sdk import PantherEvent, detection
from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

__all__ = ["login_type"]


def login_type(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A login of a non-approved type was detected for this user."""
    #from panther_base_helpers import deep_get
    # allow-list of approved login types
    APPROVED_LOGIN_TYPES = {
        "exchange",
        "google_password",
        "reauth",
        "saml",
        "unknown",
    }
    # allow-list any application names here
    APPROVED_APPLICATION_NAMES = {"saml"}

    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            from panther_detections.utils.legacy_filters import deep_get
            if event.get("type") != "login":
                return False
            if event.get("name") == "logout":
                return False
            if (
                deep_get(event,
                         "parameters", "login_type") in APPROVED_LOGIN_TYPES
                or deep_get(event, "id", "applicationName") in APPROVED_APPLICATION_NAMES
            ):
                return False
            return True

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        return (
            f"A login attempt of a non-approved type was detected for user "
            f"[{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="GSuite Login Type",
        rule_id="GSuite.LoginType",
        log_types=['GSuite.ActivityEvent'],
        severity=detection.SeverityMedium,
        description="A login of a non-approved type was detected for this user.",
        tags=['GSuite', 'Configuration Required',
              'Initial Access:Valid Accounts'],
        reports={'MITRE ATT&CK': ['TA0001:T1078']},
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#login",
        runbook="Correct the user account settings so that only logins of approved types are available.",
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
                    name="Login With Approved Type",
                    expect_match=False,
                    data=sample_logs.login_type_login_with_approved_type
                ),
                detection.JSONUnitTest(
                    name="Login With Unapproved Type",
                    expect_match=True,
                    data=sample_logs.login_type_login_with_unapproved_type
                ),
                detection.JSONUnitTest(
                    name="Non-Login event",
                    expect_match=False,
                    data=sample_logs.login_type_non_login_event
                ),
                detection.JSONUnitTest(
                    name="Saml Login Event",
                    expect_match=False,
                    data=sample_logs.login_type_saml_login_event
                ),

            ]
        )
    )
