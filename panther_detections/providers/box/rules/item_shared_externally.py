import typing

from panther_sdk import PantherEvent, detection

from panther_detections.utils.legacy_utils import deep_get

from .. import sample_logs
from .._shared import is_box_sdk_enabled, lookup_box_file, lookup_box_folder


def item_shared_externally(
    pre_filters: typing.List[detection.AnyFilter] = None,
    overrides: detection.RuleOverrides = detection.RuleOverrides(),
) -> detection.Rule:
    """A user has shared an item and it is accessible to anyone with the share link (internal or external to the company). This rule requires that the boxsdk[jwt] be installed in the environment."""

    ALLOWED_SHARED_ACCESS = {"collaborators", "company"}

    SHARE_EVENTS = {
        "CHANGE_FOLDER_PERMISSION",
        "ITEM_SHARED",
        "ITEM_SHARED_CREATE",
        "ITEM_SHARED_UPDATE",
        "SHARE",
    }

    def _title(event: PantherEvent) -> str:
        return (
            f"User [{deep_get(event, 'created_by', 'login', default='<UNKNOWN_USER>')}] shared an item "
            f"[{deep_get(event, 'source', 'item_name', default='<UNKNOWN_NAME>')}] externally."
        )

    def get_item(event: PantherEvent) -> dict:
        item_id = deep_get(event, "source", "item_id", default="")
        user_id = deep_get(event, "source", "owned_by", "id", default="")
        item = {}
        if deep_get(event, "source", "item_type") == "folder":
            item = lookup_box_folder(user_id, item_id)
        elif deep_get(event, "source", "item_type") == "file":
            item = lookup_box_file(user_id, item_id)
        return item

    def _filter(event: PantherEvent) -> bool:
        # filter events
        if event.get("event_type") not in SHARE_EVENTS:
            return False
        # only try to lookup file/folder info if sdk is enabled in the env
        if is_box_sdk_enabled():
            item = get_item(event)
            if item is not None and item.get("shared_link"):
                return deep_get(item, "shared_link", "effective_access") not in ALLOWED_SHARED_ACCESS
        return False

    return detection.Rule(
        overrides=overrides,
        enabled=False,
        name="Box item shared externally",
        rule_id="Box.Item.Shared.Externally",
        log_types=["Box.Event"],
        severity=detection.SeverityMedium,
        description="A user has shared an item and it is accessible to anyone with the share link (internal or "
        "external to the company). This rule requires that the boxsdk[jwt] be installed in the environment.",
        tags=["Box", "Exfiltration:Exfiltration Over Web Service", "Configuration Required"],
        reports={"MITRE ATT&CK": ["TA0010:T1567"]},
        reference="https://developer.box.com/reference/resources/event/",
        runbook="Investigate whether this user's activity is expected.",
        alert_title=_title,
        summary_attrs=["ip_address"],
        threshold=10,
        alert_grouping=detection.AlertGrouping(period_minutes=60),
        filters=(pre_filters or []) + [detection.PythonFilter(func=_filter)],
        unit_tests=(
            [
                detection.JSONUnitTest(name="Regular Event", expect_match=False, data=sample_logs.regular_event),
            ]
        ),
    )
