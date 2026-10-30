"""
LDAP integration layer using ldap3.
Provides high-performance, cross-platform LDAP and LDAPS queries with strict TLS Certificate Validation.
"""

import logging
import ssl
from typing import Any, Dict, List, Optional, Tuple

from ad_mcp.auth.credentials import credential_manager
from ad_mcp.config import AuthMethod, settings

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
        """Establish or return an active LDAP connection with strict TLS verification."""
        if not LDAP3_AVAILABLE:
            return False, None, "ldap3 package is not installed"

        username, password = credential_manager.get_credentials()

        # Guard: Never attempt an empty simple bind as a substitute for Kerberos/SSPI
        if not username or not password:
            if settings.auth_method == AuthMethod.WINDOWS_INTEGRATED:
                return (
                    False,
                    None,
                    "Conexao LDAP direta nao suporta autenticacao anonima. "
                    "Para autenticacao integrada do Windows (Kerberos/SSPI), utilize o backend 'powershell' ou 'hybrid'.",
                )
            return (
                False,
                None,
                "Credenciais nao encontradas. Configure as credenciais no Windows Credential Manager "
                "('AD_MCP_CREDENTIAL') ou no ambiente antes de executar consultas LDAP.",
            )

        server_host = settings.server
        port = settings.port
        use_ssl = settings.use_ssl

        try:
            tls = None
            if use_ssl:
                # Production TLS: Enforce CERT_REQUIRED and valid names
                validate_mode = ssl.CERT_REQUIRED
                if not settings.tls_validate_cert:
                    logger.warning("SECURITY WARNING: TLS certificate validation is disabled via configuration.")
                    validate_mode = ssl.CERT_NONE

                # Configure authorized DNS hostnames from configuration to prevent MITM
                valid_names = []
                if server_host and not server_host.replace(".", "").isdigit():
                    valid_names.append(server_host)
                if settings.domain:
                    valid_names.append(f"*.{settings.domain}")

                tls = ldap3.Tls(
                    validate=validate_mode,
                    ca_certs_file=settings.ca_certs_file,
                    valid_names=valid_names if valid_names else None,
                )

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

            # Check if domain\user is provided and NTLM is requested
            if username and "\\" in username and not use_ssl:
                auth_type = ldap3.NTLM

            conn = ldap3.Connection(
                server,
                user=user_dn,
                password=password,
                authentication=auth_type,
                auto_bind=False,
                read_only=True if settings.mcp_mode.value == "READ_ONLY" else False,
            )

            if not conn.bind():
                # Sanitize error message to prevent leaking any credential details
                description = conn.result.get("description", "Authentication failed")
                code = conn.result.get("result", "UNKNOWN")
                err = f"Falha na autenticacao LDAP (Codigo {code}): {description}."
                return False, None, err

            return True, conn, None

        except ssl.SSLError as se:
            logger.error(f"LDAPS SSL/TLS verification failed: {se}")
            return (
                False,
                None,
                f"Falha de validacao TLS/SSL ao conectar em {server_host}:{port}. "
                "Verifique se o certificado do Domain Controller e valido e confiavel.",
            )
        except Exception as e:
            return False, None, f"Erro de conexao LDAP: {str(e)}"

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
