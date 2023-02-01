import json
import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

__all__ = ["suspicious_logins"]


def suspicious_logins(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    def rule_filter() -> detection.PythonFilter:
        def _rule_filter(event: PantherEvent) -> bool:
            SUSPICIOUS_LOGIN_TYPES = {
                "suspicious_login",
                "suspicious_login_less_secure_app",
                "suspicious_programmatic_login",
            }

            # now a filter
            # if event["id"]["applicationName"] != "login":
            #     return False

            return bool(event.get("name") in SUSPICIOUS_LOGIN_TYPES)

        return detection.PythonFilter(func=_rule_filter)

    def _title(event: PantherEvent) -> str:
        user = event["parameters"]["affected_email_address"]
        if not user:
            user = "<UNKNOWN_USER>"
        return f"A suspicious login was reported for user [{user}]"

    def _make_context(event):
        return event

    return detection.Rule(
        overrides=overrides,
        rule_id="GSuite.SuspiciousLogins",
        name="Suspicious GSuite Login",
        log_types=["GSuite.ActivityEvent"],
        tags=["GSuite"],
        severity=detection.SeverityMedium,
        description="GSuite reported a suspicious login for this user.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#suspicious_login",
        runbook="Check out the details of the login and verify this behavior with the user to ensure the account wasn't compromised.",
        filters=(pre_filters or []) + [match_filters.deep_equal("id.applicationName", "login"), rule_filter()],
        alert_title=_title,
        alert_context=_make_context,
        summary_attrs=["actor:email"],
        unit_tests=[
            detection.JSONUnitTest(
                name="Normal Login Event",
                expect_match=False,
                data=json.dumps(
                    {
                        "id": {
                            "applicationName": "login",
                        },
                        "kind": "admin#reports#activity",
                        "type": "account_warning",
                        "name": "login_success",
                        "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
                    },
                ),
            ),
            detection.JSONUnitTest(
                name="Account Warning For Suspicious Login",
                expect_match=True,
                data=json.dumps(
                    {
                        "id": {
                            "applicationName": "login",
                        },
                        "kind": "admin#reports#activity",
                        "type": "account_warning",
                        "name": "suspicious_login",
                        "parameters": {"affected_email_address": "bobert@ext.runpanther.io"},
                    },
                ),
            ),
        ],
    )
