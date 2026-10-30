"""
Unit tests verifying LDAPS TLS security, CERT_REQUIRED enforcement, and rejection of empty binds.
"""

from ad_mcp.config import AuthMethod, settings
from ad_mcp.integrations.ldap import ldap_client


def test_ldap_rejects_empty_credentials_without_simple_bind_fallback():
    """Verify that ldap_client refuses to execute an empty simple bind if no credentials exist."""
    settings.auth_method = AuthMethod.WINDOWS_INTEGRATED

    # When no user/pass exist in WINDOWS_INTEGRATED, ldap_client must reject rather than attempting empty bind
    success, conn, err = ldap_client.get_connection()
    assert success is False
    assert conn is None
    assert "powershell" in (err or "").lower() or "credenciais" in (err or "").lower()


def test_ldaps_tls_configuration_defaults_to_cert_required():
    """Verify that tls_validate_cert defaults to True."""
    assert settings.tls_validate_cert is True

