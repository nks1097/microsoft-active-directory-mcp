"""
Security guardrails, input sanitation, and protection of critical AD objects.
"""

import re
from typing import Optional, Set

# Critical accounts that cannot be deleted or manipulated carelessly
CRITICAL_ACCOUNTS: Set[str] = {
    "administrator",
    "krbtgt",
    "guest",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "account operators",
    "backup operators",
    "server operators",
    "group policy creator owners",
    "read-only domain controllers",
    "enterprise key admins",
    "key admins",
}

# Critical OUs / Containers
CRITICAL_CONTAINERS: Set[str] = {
    "ou=domain controllers",
    "cn=builtin",
    "cn=users",
    "cn=computers",
    "cn=system",
    "cn=infrastructure",
}

# Regex for basic Distinguished Name validation
DN_PATTERN = re.compile(
    r"^(?:(?:CN|OU|DC|O|C|ST|L|STREET)\s*=\s*(?:[A-Za-z0-9_\-\.\s#]+)(?:,\s*)?)+$",
    re.IGNORECASE,
)

# Illegal characters for LDAP attribute values that could lead to injection
LDAP_UNSAFE_CHARS = re.compile(r"[\x00\*\(\)\\\/]")


def is_critical_ad_object(identifier: str) -> bool:
    """Check if object name or DN belongs to a protected AD entity."""
    clean = identifier.strip().lower()

    # Check directly by name
    if clean in CRITICAL_ACCOUNTS:
        return True

    # Check if CN or OU matches critical list
    for crit in CRITICAL_ACCOUNTS:
        if f"cn={crit}" in clean:
            return True

    for container in CRITICAL_CONTAINERS:
        if container in clean:
            return True

    return False


def validate_distinguished_name(dn: str) -> bool:
    """Validate that the string looks like a legitimate AD Distinguished Name."""
    if not dn or not isinstance(dn, str):
        return False
    dn = dn.strip()
    return bool(DN_PATTERN.match(dn))


def sanitize_ldap_filter(user_input: str) -> str:
    """
    Escape special characters in user input to prevent LDAP injection attacks.
    RFC 4515: \\ * ( ) \0
    """
    if not user_input:
        return ""
    escape_map = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    result = []
    for char in str(user_input):
        result.append(escape_map.get(char, char))
    return "".join(result)


def sanitize_powershell_string(val: Optional[str]) -> str:
    """
    Sanitize string intended for safe inclusion in PowerShell scripts.
    Never execute raw string injection; we use parameter passing, but double-guard against null-bytes and quotes.
    """
    if val is None:
        return ""
    # Strip null bytes and control chars
    cleaned = "".join(c for c in str(val) if c >= " " or c in "\t\n\r")
    # Escape single quotes for PowerShell literal single-quoted strings
    return cleaned.replace("'", "''")
