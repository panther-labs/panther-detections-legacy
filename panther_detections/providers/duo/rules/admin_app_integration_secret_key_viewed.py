import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs

def admin_app_integration_secret_key_viewed(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """An administrator viewed a Secret Key for an Application Integration"""

    def _title(event: PantherEvent) -> str:

        return (
            f"'Duo: [{event.get('username', '<NO_USER_FOUND>')}] viewed "
            f"the Secret Key for Application [{event.get('object', '<NO_OBJECT_FOUND>')}]"
        )

    return detection.Rule(
        overrides=overrides,
        name="Duo Admin App Integration Secret Key Viewed",
        rule_id="Duo.Admin.App.Integration.Secret.Key.Viewed",
        log_types=["Duo.Administrator"],
        severity=detection.SeverityMedium,
        description="An administrator viewed a Secret Key for an Application Integration",
        reference="https://duo.com/docs/adminapi",
        runbook="The security of your Duo application is tied to the security of your secret key (skey). Secure it as you would any sensitive credential. Don't share it with unauthorized individuals or email it to anyone under any circumstances!",
        filters=(pre_filters or []) + [match_filters.deep_equal("action", "integration_skey_view")],
        alert_title=_title,
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Generic Skey View",
                    expect_match=True,
                    data=sample_logs.admin_app_integration_secret_key_viewed_generic_skey_view
                ),
                detection.JSONUnitTest(
                    name="Duo app install ",
                    expect_match=False,
                    data=sample_logs.admin_app_integration_secret_key_viewed_duo_app_install_
                ),
                
            ]
        ),
        alert_grouping=detection.AlertGrouping(period_minutes=60),
    )
