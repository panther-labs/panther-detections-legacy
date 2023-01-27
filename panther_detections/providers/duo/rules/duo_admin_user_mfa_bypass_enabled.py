import typing
from panther_sdk import PantherEvent, detection

from panther_detections.utils import match_filters

from .. import sample_logs
# from .._shared import (
#     SYSTEM_LOG_TYPE,
#     create_alert_context,
#     rule_tags,
#     standard_tags,
# )

def duo_admin_user_mfa_bypass_enabled(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """An Administrator enabled a user to authenticate without MFA."""
        
    # def _title(event: PantherEvent) -> str:
    #     
    #     return "The title of the alert" 
    
                
    return detection.Rule(
        overrides=overrides,
        name="Duo Admin User MFA Bypass Enabled",
        rule_id="Duo.Admin.User.MFA.Bypass.Enabled",
        log_types=['Duo.Administrator'],
        #tags=(overrides.tags),
        #reports="",
        severity=detection.SeverityMedium,
        description="An Administrator enabled a user to authenticate without MFA.",
        #reference="",
        #runbook="",
        filters=(pre_filters or [])
        + [
            #filters
        ],
        alert_title=_title,
        #summary_attrs=(overrides.summary_attrs),
        threshold=1,
        unit_tests=(
            [
                detection.JSONUnitTest(
                    name="Account Active",
                    expect_match=False,
                    data=sample_logs.account_active
                ),
                detection.JSONUnitTest(
                    name="Account Disabled",
                    expect_match=False,
                    data=sample_logs.account_disabled
                ),
                detection.JSONUnitTest(
                    name="Bypass Enabled",
                    expect_match=True,
                    data=sample_logs.bypass_enabled
                ),
                detection.JSONUnitTest(
                    name="Phones Update",
                    expect_match=False,
                    data=sample_logs.phones_update
                ),
                
            ]
        ),
        #alert_context=,
        #alert_grouping=
        #destinations=
        #enabled=
    )