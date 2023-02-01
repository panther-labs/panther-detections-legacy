from typing import Any, Dict, Optional, Sequence, Set, Union
import os
import boto3



from panther_sdk import PantherEvent, detection

# __all__ = ["deep_equal", "deep_equal_pattern", "deep_in"]

# Helper functions for accessing Dynamo key-value store.
#
# Keys can be any string specified by rules and policies,
# values are integer counters and/or string sets.
#
# Use kv_table() if you want to interact with the table directly.
_KV_TABLE = None
_COUNT_COL = "intCount"
_STRING_SET_COL = "stringSet"

FIPS_ENABLED = os.getenv("ENABLE_FIPS", "").lower() == "true"
FIPS_SUFFIX = "-fips." + os.getenv("AWS_REGION", "") + ".amazonaws.com"


def kv_table() -> boto3.resource:
    """Lazily build key-value table resource"""
    # pylint: disable=global-statement
    global _KV_TABLE
    if not _KV_TABLE:
        # pylint: disable=no-member
        _KV_TABLE = boto3.resource(
            "dynamodb", endpoint_url="https://dynamodb" + FIPS_SUFFIX if FIPS_ENABLED else None
        ).Table("panther-kv-store")
    return _KV_TABLE


def get_counter(key: str) -> int:
    """Get a counter's current value (defaulting to 0 if key does not exist)."""
    response = kv_table().get_item(
        Key={"key": key},
        ProjectionExpression=_COUNT_COL,
    )
    return response.get("Item", {}).get(_COUNT_COL, 0)


def increment_counter(key: str, val: int = 1) -> int:
    """Increment a counter in the table.
    Args:
        key: The name of the counter (need not exist yet)
        val: How much to add to the counter
    Returns:
        The new value of the count
    """
    response = kv_table().update_item(
        Key={"key": key},
        ReturnValues="UPDATED_NEW",
        UpdateExpression="ADD #col :incr",
        ExpressionAttributeNames={"#col": _COUNT_COL},
        ExpressionAttributeValues={":incr": val},
    )

    # Numeric values are returned as decimal.Decimal
    return response["Attributes"][_COUNT_COL].to_integral_value()


def reset_counter(key: str) -> None:
    """Reset a counter to 0."""
    kv_table().put_item(Item={"key": key, _COUNT_COL: 0})


def set_key_expiration(key: str, epoch_seconds: int) -> None:
    """Configure the key to automatically expire at the given time.
    DynamoDB typically deletes expired items within 48 hours of expiration.
    Args:
        key: The name of the counter
        epoch_seconds: When you want the counter to expire (set to 0 to disable)
    """
    kv_table().update_item(
        Key={"key": key},
        UpdateExpression="SET expiresAt = :time",
        ExpressionAttributeValues={":time": epoch_seconds},
    )


def get_string_set(key: str) -> Set[str]:
    """Get a string set's current value (defaulting to empty set if key does not exit)."""
    response = kv_table().get_item(
        Key={"key": key},
        ProjectionExpression=_STRING_SET_COL,
    )
    return response.get("Item", {}).get(_STRING_SET_COL, set())


def put_string_set(key: str, val: Sequence[str], epoch_seconds: int = None) -> None:
    """Overwrite a string set under the given key.
    This is faster than (reset_string_set + add_string_set) if you know exactly what the contents
    of the set should be.
    Args:
        key: The name of the string set
        val: A list/set/tuple of strings to store
        epoch_seconds: (Optional) Set string expiration time
    """
    if not val:
        # Can't put an empty string set - remove it instead
        reset_string_set(key)
    else:
        kv_table().put_item(Item={"key": key, _STRING_SET_COL: set(val)})
    if epoch_seconds:
        set_key_expiration(key, epoch_seconds)


def add_to_string_set(key: str, val: Union[str, Sequence[str]]) -> Set[str]:
    """Add one or more strings to a set.
    Args:
        key: The name of the string set
        val: Either a single string or a list/tuple/set of strings to add
    Returns:
        The new value of the string set
    """
    if isinstance(val, str):
        item_value = {val}
    else:
        item_value = set(val)
        if not item_value:
            # We can't add empty sets, just return the existing value instead
            return get_string_set(key)

    response = kv_table().update_item(
        Key={"key": key},
        ReturnValues="UPDATED_NEW",
        UpdateExpression="ADD #col :ss",
        ExpressionAttributeNames={"#col": _STRING_SET_COL},
        ExpressionAttributeValues={":ss": item_value},
    )
    return response["Attributes"][_STRING_SET_COL]


def remove_from_string_set(key: str, val: Union[str, Sequence[str]]) -> Set[str]:
    """Remove one or more strings from a set.
    Args:
        key: The name of the string set
        val: Either a single string or a list/tuple/set of strings to remove
    Returns:
        The new value of the string set
    """
    if isinstance(val, str):
        item_value = {val}
    else:
        item_value = set(val)
        if not item_value:
            # We can't remove empty sets, just return the existing value instead
            return get_string_set(key)

    response = kv_table().update_item(
        Key={"key": key},
        ReturnValues="UPDATED_NEW",
        UpdateExpression="DELETE #col :ss",
        ExpressionAttributeNames={"#col": _STRING_SET_COL},
        ExpressionAttributeValues={":ss": item_value},
    )
    return response["Attributes"][_STRING_SET_COL]


def reset_string_set(key: str) -> None:
    """Reset a string set to empty."""
    kv_table().update_item(
        Key={"key": key},
        UpdateExpression="REMOVE #col",
        ExpressionAttributeNames={"#col": _STRING_SET_COL},
    )


# def deep_exists(path: str) -> detection.PythonFilter:
#     """Returns True when a value at the provided path exists"""

#     def _deep_exists(event: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             event,
#         )

#         return bool(actual is not None)

#     return detection.PythonFilter(func=_deep_exists)


# def deep_not_exists(path: str) -> detection.PythonFilter:
#     """Returns True when a value at the provided path does not exist"""

#     def _deep_not_exists(event: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             event,
#         )

#         return bool(actual is None)

#     return detection.PythonFilter(func=_deep_not_exists)


# def deep_equal(path: str, value: typing.Any) -> detection.PythonFilter:
#     """Returns True when the provided value equals the value at the provided path"""

#     def _deep_equal(event: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             event,
#         )

#         return bool(actual == value)

#     return detection.PythonFilter(func=_deep_equal)


# def deep_not_equal(path: str, value: typing.Any) -> detection.PythonFilter:
#     """Returns True when the provided value does not equal the value at the provided path"""

#     def _deep_not_equal(event: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             event,
#         )

#         return bool(actual != value)

#     return detection.PythonFilter(func=_deep_not_equal)


# def deep_equal_pattern(path: str, pattern: str) -> detection.PythonFilter:
#     """Returns True when the provided pattern matches the value at the provided path using the 're' module"""

#     def _deep_equal_pattern(evt: PantherEvent) -> bool:
#         import collections
#         import functools
#         import re

#         keys = path.split(".")
#         regex = re.compile(pattern)

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(regex.search(actual))

#     return detection.PythonFilter(func=_deep_equal_pattern)


# def deep_not_equal_pattern(path: str, pattern: str) -> detection.PythonFilter:
#     """Returns True when the provided pattern does not match the value at the provided path using the 're' module"""

#     def _deep_not_equal_pattern(evt: PantherEvent) -> bool:
#         import collections
#         import functools
#         import re

#         keys = path.split(".")
#         regex = re.compile(pattern)

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return not bool(regex.search(actual))

#     return detection.PythonFilter(func=_deep_not_equal_pattern)


# def deep_in(path: str, value: typing.List[typing.Any]) -> detection.PythonFilter:
#     """Returns True when one of the provided values are equal to the value at the provided path"""

#     def _deep_in(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return actual in value

#     return detection.PythonFilter(
#         func=_deep_in,
#     )


# def deep_not_in(path: str, value: typing.List[typing.Any]) -> detection.PythonFilter:
#     """Returns True when none of the provided values are equal to the value at the provided path"""

#     def _deep_not_in(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return actual not in value

#     return detection.PythonFilter(
#         func=_deep_not_in,
#     )


# def deep_less_than(path: str, value: typing.Union[int, float]) -> detection.PythonFilter:
#     """Returns True if the value at the provided path is less than a value"""

#     def _deep_less_than(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(actual < value)

#     return detection.PythonFilter(
#         func=_deep_less_than,
#     )


# def deep_less_than_or_equal(path: str, value: typing.Union[int, float]) -> detection.PythonFilter:
#     """Returns True if the value at the provided path is less than or equal to a value"""

#     def _deep_less_than_or_equal(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(actual <= value)

#     return detection.PythonFilter(
#         func=_deep_less_than_or_equal,
#     )


# def deep_greater_than(path: str, value: typing.Union[int, float]) -> detection.PythonFilter:
#     """Returns True if the value at the provided path is greater than a value"""

#     def _deep_greater_than(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(actual > value)

#     return detection.PythonFilter(
#         func=_deep_greater_than,
#     )


# def deep_greater_than_or_equal(path: str, value: typing.Union[int, float]) -> detection.PythonFilter:
#     """Returns True if the value at the provided path is greater than or equal to a value"""

#     def _deep_greater_than_or_equal(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(actual >= value)

#     return detection.PythonFilter(
#         func=_deep_greater_than_or_equal,
#     )


# def deep_between(
#     path: str,
#     val_min: typing.Union[int, float],
#     val_max: typing.Union[int, float],
# ) -> detection.PythonFilter:
#     """Returns True if the value at the provided path is between (or equal to) a maximum and minimum"""

#     if val_min >= val_max:
#         raise RuntimeError("deep_between: min must be greater than max")

#     def _deep_between(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(val_min <= actual <= val_max)

#     return detection.PythonFilter(
#         func=_deep_between,
#     )


# def deep_between_exclusive(
#     path: str,
#     val_min: typing.Union[int, float],
#     val_max: typing.Union[int, float],
# ) -> detection.PythonFilter:
#     """Returns True if the value at the provided path is between, but not equal to, a maximum and minimum"""

#     if val_min >= val_max:
#         raise RuntimeError("deep_between_exclusive: min must be greater than max")

#     def _deep_between_exclusive(evt: PantherEvent) -> bool:
#         import collections
#         import functools

#         keys = path.split(".")

#         actual = functools.reduce(
#             lambda d, key: d.get(key, None) if isinstance(d, collections.abc.Mapping) else None,
#             keys,
#             evt,
#         )

#         return bool(val_min < actual < val_max)

#     return detection.PythonFilter(
#         func=_deep_between_exclusive,
#     )
