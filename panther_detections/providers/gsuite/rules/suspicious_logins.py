import json
import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

from .._shared import rule_tags

__all__ = ["suspicious_logins"]


def suspicious_logins(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
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
        log_types=schema.LogTypeGSuiteActivityEvent,
        tags=rule_tags(),
        severity=detection.SeverityMedium,
        description="GSuite reported a suspicious login for this user.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#suspicious_login",
        runbook="Check out the details of the login and verify this behavior with the user"
        "to ensure the account wasn't compromised.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "login"),
            match_filters.deep_in(
                "name",
                {
                    "suspicious_login",
                    "suspicious_login_less_secure_app",
                    "suspicious_programmatic_login",
                },
            ),
        ],
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
