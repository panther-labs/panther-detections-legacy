from collections.abc import Mapping
from fnmatch import fnmatch
from functools import reduce
from typing import Sequence


def deep_get(dictionary: dict, *keys, default=None):
    """Safely return the value of an arbitrarily nested map
    Inspired by https://bit.ly/3a0hq9E
    """
    return reduce(lambda d, key: d.get(key, default) if isinstance(d, Mapping) else default, keys, dictionary)


def pattern_match_list(string_to_match: str, patterns: Sequence[str]):
    """Check that a string matches any pattern in a given list.
    From panther_base_helpers"""

    return any(fnmatch(string_to_match, p) for p in patterns)
