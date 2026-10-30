"""
LDAP integration layer using ldap3.
Provides high-performance, cross-platform LDAP and LDAPS queries.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from ad_mcp.auth.credentials import credential_manager
from ad_mcp.config import settings

logger = logging.getLogger("ad_mcp.ldap")

try:
    import ldap3

    LDAP3_AVAILABLE = True
except ImportError:
    LDAP3_AVAILABLE = False


class LdapClient:
    """LDAP/LDAPS connection manager and query executor."""

    def __init__(self):
        self._server = None
        self._conn = None

    def is_available(self) -> bool:
        return LDAP3_AVAILABLE

    def get_connection(self) -> Tuple[bool, Any, Optional[str]]:
        """Establish or return an active LDAP connection."""
        if not LDAP3_AVAILABLE:
            return False, None, "ldap3 package is not installed"

        username, password = credential_manager.get_credentials()
        server_host = settings.server
        port = settings.port
        use_ssl = settings.use_ssl

        try:
            tls = None
            if use_ssl:
                tls = ldap3.Tls(validate=ldap3.ssl.CERT_NONE)

            server = ldap3.Server(
                server_host,
                port=port,
                use_ssl=use_ssl,
                tls=tls,
                get_info=ldap3.ALL,
                connect_timeout=settings.timeout_seconds,
            )

            auth_type = ldap3.SIMPLE
            user_dn = username

            # Check if domain\user is provided and NTLM can be used
            if username and "\\" in username:
                auth_type = ldap3.NTLM

            conn = ldap3.Connection(
                server,
                user=user_dn,
                password=password,
                authentication=auth_type,
                auto_bind=False,
                read_only=settings.mcp_mode.value == "READ_ONLY",
            )

            if not conn.bind():
                err = f"LDAP bind failed: {conn.result.get('description', 'Unknown error')} - {conn.result.get('message', '')}"
                return False, None, err

            return True, conn, None

        except Exception as e:
            return False, None, f"LDAP connection error: {str(e)}"

    def search(
        self,
        search_filter: str,
        attributes: Optional[List[str]] = None,
        search_base: Optional[str] = None,
        search_scope: str = "SUBTREE",
        size_limit: Optional[int] = None,
    ) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """Perform an LDAP search and return formatted attribute dictionaries."""
        success, conn, err = self.get_connection()
        if not success or conn is None:
            return False, [], err

        base_dn = search_base or settings.effective_base_dn
        scope = ldap3.SUBTREE if search_scope == "SUBTREE" else ldap3.LEVEL
        attrs = attributes or ldap3.ALL_ATTRIBUTES
        limit = size_limit or settings.max_page_size

        try:
            conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=scope,
                attributes=attrs,
                size_limit=limit,
            )

            entries: List[Dict[str, Any]] = []
            for entry in conn.entries:
                item: Dict[str, Any] = {"dn": entry.entry_dn}
                for attr in entry.entry_attributes:
                    val = getattr(entry, attr).value
                    # Format byte strings or raw objects if needed
                    if isinstance(val, bytes):
                        val = val.hex()
                    item[attr] = val
                entries.append(item)

            conn.unbind()
            return True, entries, None

        except Exception as e:
            return False, [], f"LDAP search failed: {str(e)}"


ldap_client = LdapClient()
