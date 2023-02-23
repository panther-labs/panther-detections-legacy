import json

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

__all__ = ["two_step_verification"]


def two_step_verification(
    extensions: detection.RuleExtensions = detection.RuleExtensions(),
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    def _title(event: PantherEvent) -> str:
        return (
            f"Two step verification was disabled for user"
            f" [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        extensions=extensions,
        rule_id="GSuite.TwoStepVerification",
        name="GSuite User Two Step Verification Change",
        log_types=schema.LogTypeGSuiteActivityEvent,
        tags=["GSuite", "Defense Evasion:Modify Authentication Process"],
        severity=detection.SeverityLow,
        description="A user disabled two step verification for themselves.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts",
        runbook="Investigate the behavior that got the account suspended. Verify with the user"
        "that this intended behavior. If not, the account may have been compromised.",
        filters=[
            match_filters.deep_equal("id.applicationName", "user_accounts"),
            match_filters.deep_equal("type", "2sv_change"),
            match_filters.deep_equal("name", "2sv_disable"),
        ],
        alert_title=_title,
        # alert_context=,
        summary_attrs=["actor:email"],
        unit_tests=[
            detection.JSONUnitTest(
                name="Two Step Verification Disabled",
                expect_match=True,
                data=json.dumps(
                    {
                        "id": {
                            "applicationName": "user_accounts",
                        },
                        "actor": {
                            "callerType": "USER",
                            "email": "some.user@somedomain.com",
                        },
                        "kind": "admin#reports#activity",
                        "type": "2sv_change",
                        "name": "2sv_disable",
                    }
                ),
            ),
        ],
    )
