"""
Credential and authentication handling for Active Directory MCP Server.
"""

from typing import Optional, Tuple

from ad_mcp.config import settings


class CredentialManager:
    """Manages credentials safely without exposing plain text."""

    @staticmethod
    def get_credentials() -> Tuple[Optional[str], Optional[str]]:
        """Return username and password string securely."""
        user = settings.username
        password = settings.password.get_secret_value() if settings.password else None
        return user, password

    @staticmethod
    def get_domain_and_user() -> Tuple[str, str]:
        """Split user into domain and samAccountName."""
        user = settings.username or ""
        if "\\" in user:
            dom, u = user.split("\\", 1)
            return dom, u
        if "@" in user:
            u, dom = user.split("@", 1)
            return dom, u
        return settings.domain, user


credential_manager = CredentialManager()
