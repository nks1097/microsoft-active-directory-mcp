"""
Bridge layer unifying PowerShell (RSAT & ADSI/.NET fallback) and LDAP integrations.
Provides high-level AD operations with seamless fallback across environments.
"""

import logging
from typing import Any, Optional, Tuple

from ad_mcp.auth.credentials import credential_manager
from ad_mcp.authorization.guardrails import sanitize_powershell_string
from ad_mcp.config import settings
from ad_mcp.integrations.ldap import ldap_client
from ad_mcp.integrations.powershell import powershell_client

logger = logging.getLogger("ad_mcp.bridge")


class ADBridge:
    """Unified bridge executing Active Directory operations."""

    def __init__(self):
        self.ps = powershell_client
        self.ldap = ldap_client

    def _get_ps_credential_block(self) -> str:
        """Generate PowerShell snippet for credentials if configured."""
        user, password = credential_manager.get_credentials()
        server = settings.server
        domain = settings.domain

        if user and password:
            safe_user = sanitize_powershell_string(user)
            safe_pass = sanitize_powershell_string(password)
            return f"""
            $secPass = ConvertTo-SecureString '{safe_pass}' -AsPlainText -Force
            $cred = New-Object System.Management.Automation.PSCredential('{safe_user}', $secPass)
            $adServer = '{sanitize_powershell_string(server)}'
            $adDomain = '{sanitize_powershell_string(domain)}'
            $adUser = '{safe_user}'
            $adPass = '{safe_pass}'
            """
        else:
            return f"""
            $cred = $null
            $adServer = '{sanitize_powershell_string(server)}'
            $adDomain = '{sanitize_powershell_string(domain)}'
            $adUser = $null
            $adPass = $null
            """

    def run_query(
        self,
        rsat_script: str,
        adsi_fallback: Optional[str] = None,
        ldap_fallback_filter: Optional[str] = None,
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Execute an AD read query trying RSAT -> ADSI/.NET -> LDAP.
        """
        cred_header = self._get_ps_credential_block()

        # 1. Try RSAT if available on Windows
        if self.ps.is_available() and self.ps.check_rsat():
            full_script = f"""
            {cred_header}
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            {rsat_script}
            """
            success, data, err = self.ps.execute_script(full_script, as_json=True)
            if success:
                return True, data, None
            logger.warning(f"RSAT query failed: {err}. Attempting fallback...")

        # 2. Try ADSI / .NET PowerShell fallback if provided
        if self.ps.is_available() and adsi_fallback:
            full_script = f"""
            {cred_header}
            {adsi_fallback}
            """
            success, data, err = self.ps.execute_script(full_script, as_json=True)
            if success:
                return True, data, None
            logger.warning(f"ADSI fallback query failed: {err}")

        # 3. Try pure LDAP if available and filter is provided
        if ldap_fallback_filter and self.ldap.is_available():
            success, entries, err = self.ldap.search(ldap_fallback_filter)
            if success:
                return True, entries, None

        # 4. If RSAT was attempted but errored without fallbacks
        if self.ps.is_available():
            full_script = f"""
            {cred_header}
            {rsat_script}
            """
            return self.ps.execute_script(full_script, as_json=True)

        return False, None, "No available integration backend could execute the query."

    def run_mutation(
        self,
        rsat_script: str,
        adsi_fallback: Optional[str] = None,
    ) -> Tuple[bool, Any, Optional[str]]:
        """
        Execute an AD write/mutation operation.
        Enforces a hard security barrier if server is in READ_ONLY mode.
        """
        from ad_mcp.config import OperationMode

        if settings.mcp_mode == OperationMode.READ_ONLY:
            logger.warning("HARD BLOCK: Mutation rejected because server is operating in READ_ONLY mode.")
            return False, None, "Operacao de escrita bloqueada: O servidor MCP esta configurado em modo READ_ONLY."

        cred_header = self._get_ps_credential_block()

        # RSAT is the preferred, robust way for AD DS mutations
        if self.ps.is_available():
            full_script = f"""
            {cred_header}
            Import-Module ActiveDirectory -ErrorAction SilentlyContinue
            {rsat_script}
            """
            success, data, err = self.ps.execute_script(full_script, as_json=True)
            if success:
                return True, data, None
            if adsi_fallback:
                fallback_script = f"""
                {cred_header}
                {adsi_fallback}
                """
                return self.ps.execute_script(fallback_script, as_json=True)
            return False, None, err

        return False, None, "PowerShell integration is required for this administrative operation."


ad_bridge = ADBridge()
