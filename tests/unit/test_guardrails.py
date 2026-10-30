"""
Unit tests for security guardrails, injection prevention, and critical object protection.
"""

from ad_mcp.authorization.guardrails import (
    is_critical_ad_object,
    sanitize_ldap_filter,
    sanitize_powershell_string,
    validate_distinguished_name,
)
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.config import OperationMode, settings


def test_critical_objects_detection():
    assert is_critical_ad_object("Administrator") is True
    assert is_critical_ad_object("krbtgt") is True
    assert is_critical_ad_object("Domain Admins") is True
    assert is_critical_ad_object("CN=Domain Admins,CN=Users,DC=test,DC=local") is True
    assert is_critical_ad_object("OU=Domain Controllers,DC=test,DC=local") is True

    # Standard users are not critical
    assert is_critical_ad_object("john.doe") is False
    assert is_critical_ad_object("OU=Finance,DC=test,DC=local") is False


def test_critical_object_deletion_is_blocked():
    settings.mcp_mode = OperationMode.FULL_ADMIN
    settings.protect_critical_objects = True

    # Attempting to delete Domain Admins must be blocked even in FULL_ADMIN
    allowed, resp = auth_engine.authorize_execution(
        "ad_delete_group",
        {"identity": "Domain Admins"},
        target_object="Domain Admins",
    )
    assert allowed is False
    assert resp.error_code == "CRITICAL_OBJECT_PROTECTED"


def test_distinguished_name_validation():
    assert validate_distinguished_name("CN=John Doe,OU=Users,DC=domain,DC=local") is True
    assert validate_distinguished_name("OU=Sales,DC=domain,DC=com") is True
    assert validate_distinguished_name("invalid_dn_without_rdn") is False
    assert validate_distinguished_name("") is False


def test_ldap_filter_sanitization():
    # RFC 4515 escape characters: \ * ( ) \0
    unsafe = r"admin*)(uid=*))(|(uid=*"
    sanitized = sanitize_ldap_filter(unsafe)
    assert r"\2a" in sanitized
    assert r"\28" in sanitized
    assert r"\29" in sanitized
    assert "*)" not in sanitized


def test_powershell_string_sanitization():
    raw = "User's Account; Remove-Item C:\\ -Recurse"
    safe = sanitize_powershell_string(raw)
    assert "''" in safe  # Single quote escaped as ''
    assert "\x00" not in safe
