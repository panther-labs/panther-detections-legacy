from typing import Any, Dict, List

from panther_sdk import PantherEvent

from panther_detections.utils import standard_tags

__all__ = [
    "rule_tags",
    "SHARED_TAGS",
    "create_alert_context",
]

SHARED_TAGS = [
    "Crowdstrike",
    #standard_tags.IDENTITY_AND_ACCESS_MGMT,
]

def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


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
