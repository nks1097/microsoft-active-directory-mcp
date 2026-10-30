"""
Credential and authentication handling for Active Directory MCP Server.
Supports:
1. Windows Integrated Authentication (Kerberos / SSPI - Zero Password required)
2. Windows Credential Manager / DPAPI Vault (Encrypted OS-level storage)
3. Secure Environment Variables (Container / Orchestrator injection)
"""

import logging
from typing import Optional, Tuple

from ad_mcp.config import AuthMethod, settings

logger = logging.getLogger("ad_mcp.auth")

try:
    import win32cred

    WIN32CRED_AVAILABLE = True
except ImportError:
    WIN32CRED_AVAILABLE = False


class CredentialManager:
    """Manages credentials securely without exposing plain text in configuration files."""

    @staticmethod
    def get_credentials() -> Tuple[Optional[str], Optional[str]]:
        """
        Return username and password string securely using configured enterprise auth method.
        """
        method = settings.auth_method

        # 1. Forced Windows Integrated Authentication (Kerberos / SSPI)
        if method == AuthMethod.WINDOWS_INTEGRATED:
            logger.info("Using Windows Integrated Authentication (Kerberos/SSPI). No password required.")
            return None, None

        # 2. Windows Credential Manager (Cofre de Credenciais do Windows)
        if method in (AuthMethod.CREDENTIAL_MANAGER, AuthMethod.AUTO) and WIN32CRED_AVAILABLE:
            try:
                cred = win32cred.CredRead(settings.credential_target, win32cred.CRED_TYPE_GENERIC, 0)
                user = cred["UserName"]
                if user and "\\\\" in user:
                    user = user.replace("\\\\", "\\")
                blob = cred["CredentialBlob"]
                password = blob.decode("utf-16le") if isinstance(blob, bytes) else str(blob)
                logger.info(f"Loaded credentials securely from Windows Credential Manager target '{settings.credential_target}'")
                return user, password
            except Exception as e:
                if method == AuthMethod.CREDENTIAL_MANAGER:
                    logger.error(f"Failed to read from Windows Credential Manager '{settings.credential_target}': {e}")
                    raise RuntimeError(f"Windows Credential Manager target '{settings.credential_target}' not found or inaccessible.") from e

        # 3. Environment Variables fallback (Memory / Container Secrets)
        user = settings.username
        password = settings.password.get_secret_value() if settings.password else None
        if user and password:
            return user, password

        # 4. If nothing is explicitly provided, default to Windows Integrated Authentication
        logger.info("No credentials in Vault or Environment. Defaulting to Windows Integrated Authentication (SSPI/Kerberos).")
        return None, None

    @staticmethod
    def store_in_vault(target: str, username: str, password: str) -> bool:
        """Helper to store credentials encrypted into Windows Credential Manager."""
        if not WIN32CRED_AVAILABLE:
            raise RuntimeError("win32cred is not available on this platform.")
        win32cred.CredWrite(
            {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": target,
                "UserName": username,
                "CredentialBlob": password,
                "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
            },
            0,
        )
        return True

    @staticmethod
    def delete_from_vault(target: str) -> bool:
        """Helper to delete credentials from Windows Credential Manager."""
        if not WIN32CRED_AVAILABLE:
            return False
        try:
            win32cred.CredDelete(target, win32cred.CRED_TYPE_GENERIC, 0)
            return True
        except Exception:
            return False

    @staticmethod
    def get_domain_and_user() -> Tuple[str, str]:
        """Split user into domain and samAccountName."""
        user, _ = CredentialManager.get_credentials()
        raw_user = user or settings.username or ""
        if "\\" in raw_user:
            dom, u = raw_user.split("\\", 1)
            return dom, u
        if "@" in raw_user:
            u, dom = raw_user.split("@", 1)
            return dom, u
        return settings.domain, raw_user


credential_manager = CredentialManager()
