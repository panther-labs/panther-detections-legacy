from typing import List

__all__ = [
    "rule_tags",
    "SHARED_TAGS",
    "SUSPICIOUS_COMMANDS",
    "SCAN_COMMANDS",
    "USER_CREATE_PATTERNS",
]

SHARED_TAGS = [
    "Teleport",
]


def rule_tags(*extra_tags: str) -> List[str]:
    return [*SHARED_TAGS, *extra_tags]

SUSPICIOUS_COMMANDS = ["nc", "wget"]

SCAN_COMMANDS = ["arp", "arp-scan", "fping", "nmap"]

USER_CREATE_PATTERNS = [
    "chage",  # user password expiry
    "passwd",  # change passwords for users
    "user*",  # create, modify, and delete users
]