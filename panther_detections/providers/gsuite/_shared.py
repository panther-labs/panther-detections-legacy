from typing import Dict, List

from panther_sdk import PantherEvent

__all__ = [
    "SHARED_TAGS",
    "rule_tags",
    "GSUITE_PARAMETER_VALUES",
    "gsuite_parameter_lookup",
    "gsuite_details_lookup",
]

# # # # # # # # # # # # # #
#      GSuite Helpers     #
# # # # # # # # # # # # # #


# GSuite parameters are formatted as a list of dictionaries, where each dictionary has a 'name' key
# that maps to the name of the parameter, and one key from GSUITE_PARAMETER_VALUES that maps to the
# value of the parameter. This means to lookup the value of a particular parameter, you must
# traverse the entire list of parameters to find it and then know (or guess) what type of value it
# contains. This helper function handles that for us.
#
# Example parameters list:
# parameters = [
#   {
#       "name": "event_id",
#       "value": "abc123"
#   },
#   {
#       "name": "start_time",
#       "intValue": 63731901000
#   },
#   {
#       "name": "end_time",
#       "intValue": 63731903000
#   },
#   {
#       "name": "things",
#       "multiValue": [ "DRIVE" , "MEME"]
#   }
# ]

SHARED_TAGS = [
    "GSuite",
]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]


GSUITE_PARAMETER_VALUES = [
    "value",
    "intValue",
    "boolValue",
    "multiValue",
    "multiIntValue",
    "messageValue",
    "multiMessageValue",
]


def gsuite_parameter_lookup(parameters: List, key: str):
    for param in parameters:
        if param["name"] != key:
            continue
        for value in GSUITE_PARAMETER_VALUES:
            if value in param:
                return param[value]
        return None
    return None


# GSuite event details are formatted as a list of dictionaries. Each entry has a 'type' and 'name'.
#
# In order to find the event details of interest, you must loop through
# the list searching for a particular type and name.
#
# This helper function handles the looping functionality that is common in many of the gsuite rules
def gsuite_details_lookup(detail_type: str, detail_names: Dict, evt: PantherEvent) -> Dict:
    for details in evt.get("events", {}):
        if details.get("type") == detail_type and details.get("name") in detail_names:
            return details
    # not found, return empty dict
    return {}
