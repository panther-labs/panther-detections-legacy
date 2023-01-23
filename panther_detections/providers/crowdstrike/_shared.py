from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags

# __all__ = [
#     "rule_tags",
#     "SYSTEM_LOG_TYPE",
#     "SUPPORT_ACCESS_EVENTS",
#     "SUPPORT_RESET_EVENTS",
#     "SHARED_TAGS",
#     "SHARED_SUMMARY_ATTRS",
#     "create_alert_context",
# ]

# SYSTEM_LOG_TYPE = "Crowdstrike."

# SUPPORT_ACCESS_EVENTS = [
#     "user.session.impersonation.grant",
#     "user.session.impersonation.initiate",
# ]

# SUPPORT_RESET_EVENTS = [
#     "user.account.reset_password",
#     "user.mfa.factor.update",
#     "system.mfa.factor.deactivate",
#     "user.mfa.attempt_bypass",
# ]

SHARED_TAGS = [
    "Crowdstrike",
    #standard_tags.IDENTITY_AND_ACCESS_MGMT,
]

# SHARED_SUMMARY_ATTRS = [
#     "eventType",
#     "severity",
#     "displayMessage",
#     "p_any_ip_addresses",
# ]


# def rule_tags(*extra_tags: str) -> List[str]:
#     return [*SHARED_TAGS, *extra_tags]


def create_alert_context(event: PantherEvent) -> Dict[str, Any]:
    """Returns common context for Crowdstrike detections"""

    return {
        "user": event.get("UserName", ""),
        "console-link": event.get("FalconHostLink", ""),
        "commandline": event.get("CommandLine", ""),
        "parentcommandline": event.get("ParentCommandLine", ""),
        "filename": event.get("FileName", ""),
        "filepath": event.get("FilePath", ""),
        "description": event.get("DetectDescription", ""),
        "action": event.get("PatternDispositionDescription", ""),
    }
