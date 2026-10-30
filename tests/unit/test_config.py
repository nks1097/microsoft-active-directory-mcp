"""
Unit tests for configuration and settings.
"""

from ad_mcp.config import BackendType, OperationMode, Settings


def test_default_settings():
    s = Settings()
    assert s.mcp_mode == OperationMode.READ_ONLY
    assert s.protect_critical_objects is True
    assert s.allow_destructive_operations is False
    assert s.backend in [BackendType.HYBRID, BackendType.POWERSHELL, BackendType.LDAP]


def test_base_dn_calculation():
    s = Settings(domain="corp.contoso.com")
    assert s.effective_base_dn == "DC=corp,DC=contoso,DC=com"

    s2 = Settings(domain="corp.contoso.com", base_dn="DC=custom,DC=local")
    assert s2.effective_base_dn == "DC=custom,DC=local"
