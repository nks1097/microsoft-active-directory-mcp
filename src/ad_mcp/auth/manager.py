"""
Authentication and connection manager.
"""

from typing import Any, Dict

from ad_mcp.auth.credentials import credential_manager
from ad_mcp.config import settings


class AuthManager:
    """Provides authentication status and details for diagnostics."""

    @staticmethod
    def get_auth_summary() -> Dict[str, Any]:
        username, has_password = credential_manager.get_credentials()
        return {
            "server": settings.server,
            "domain": settings.domain,
            "port": settings.port,
            "use_ssl": settings.use_ssl,
            "authenticated_as": username or "Integrated / Machine Account",
            "has_password": bool(has_password),
            "backend": settings.backend.value,
            "mode": settings.mcp_mode.value,
        }


auth_manager = AuthManager()
