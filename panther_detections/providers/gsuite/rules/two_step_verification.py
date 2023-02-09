import json
import typing

from panther_sdk import PantherEvent, detection, schema

from panther_detections.utils import match_filters

__all__ = ["two_step_verification"]


def two_step_verification(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    def rule_filter() -> detection.PythonFilter:
        def _rule(event: PantherEvent) -> bool:
            if event.get("type") == "2sv_change" and event.get("name") == "2sv_disable":
                return True
            return False

        return detection.PythonFilter(func=_rule)

    def _title(event: PantherEvent) -> str:
        # from ..global_helpers import deep_get
        return (
            f"Two step verification was disabled for user"
            f" [{event.deep_get('actor', 'email', default='<UNKNOWN_USER>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        rule_id="GSuite.TwoStepVerification",
        name="GSuite User Two Step Verification Change",
        log_types=schema.LogTypeGSuiteActivityEvent,
        tags=["GSuite", "Defense Evasion:Modify Authentication Process"],
        severity=detection.SeverityLow,
        description="A user disabled two step verification for themselves.",
        reference="https://developers.google.com/admin-sdk/reports/v1/appendix/activity/user-accounts",
        runbook="Investigate the behavior that got the account suspended. Verify with the user"
        "that this intended behavior. If not, the account may have been compromised.",
        filters=(pre_filters or [])
        + [
            match_filters.deep_equal("id.applicationName", "user_accounts"),
            rule_filter(),
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
