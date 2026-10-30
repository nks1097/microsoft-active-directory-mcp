"""
Unit tests for Windows Credential Manager integration (store, retrieve, delete, validation).
"""

import pytest

from ad_mcp.auth.credentials import WIN32CRED_AVAILABLE, CredentialManager
from ad_mcp.config import AuthMethod, settings


@pytest.mark.skipif(not WIN32CRED_AVAILABLE, reason="win32cred only available on Windows")
def test_windows_credential_manager_roundtrip():
    target = "TEST_VAULT_ROUNDTRIP_123"
    user = "CORP\\svc_test"
    password = "SuperP@ssw0rd!#$2026"

    # 1. Store
    assert CredentialManager.store_in_vault(target, user, password) is True

    # 2. Retrieve
    settings.auth_method = AuthMethod.CREDENTIAL_MANAGER
    settings.credential_target = target

    retrieved_user, retrieved_pass = CredentialManager.get_credentials()
    assert retrieved_user == user
    assert retrieved_pass == password

    # 3. Clean up (delete)
    assert CredentialManager.delete_from_vault(target) is True

    # 4. Confirm it is deleted
    with pytest.raises(RuntimeError):
        CredentialManager.get_credentials()


def test_store_in_vault_empty_inputs_rejected():
    with pytest.raises(ValueError):
        CredentialManager.store_in_vault("", "user", "pass")
    with pytest.raises(ValueError):
        CredentialManager.store_in_vault("target", "", "pass")
    with pytest.raises(ValueError):
        CredentialManager.store_in_vault("target", "user", "")
