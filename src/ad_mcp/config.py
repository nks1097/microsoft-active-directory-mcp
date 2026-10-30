"""
Configuration module for Microsoft Active Directory MCP Server.
"""

from enum import Enum
from typing import Optional

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class OperationMode(str, Enum):
    """MCP Server Operation Modes."""

    READ_ONLY = "READ_ONLY"
    WRITE_APPROVAL = "WRITE_APPROVAL"
    FULL_ADMIN = "FULL_ADMIN"


class AuthMethod(str, Enum):
    """Authentication Method for Active Directory."""

    AUTO = "auto"
    WINDOWS_INTEGRATED = "windows_integrated"
    CREDENTIAL_MANAGER = "credential_manager"
    ENV = "env"


class BackendType(str, Enum):
    """AD Integration Backend."""

    HYBRID = "hybrid"
    POWERSHELL = "powershell"
    LDAP = "ldap"


class Settings(BaseSettings):
    """Active Directory MCP Server Settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="AD_",
        case_sensitive=False,
        extra="ignore",
    )

    # Operational Mode & Safety
    mcp_mode: OperationMode = Field(
        default=OperationMode.READ_ONLY,
        description="Operating mode: READ_ONLY, WRITE_APPROVAL, or FULL_ADMIN",
    )
    protect_critical_objects: bool = Field(
        default=True,
        description="Protect critical AD objects (Domain Admins, KRBTGT, Domain Controllers) from modification",
    )
    allow_destructive_operations: bool = Field(
        default=False,
        description="Globally permit deletion operations (ad_delete_*) if mode permits",
    )
    allow_bulk_operations: bool = Field(
        default=False,
        description="Permit bulk modifications affecting more than 10 objects at once",
    )
    approval_token_ttl_seconds: int = Field(
        default=300,
        description="Lifetime of write confirmation tokens in seconds (5 minutes default)",
    )

    # Active Directory Connection
    server: str = Field(
        default="127.0.0.1",
        description="Domain Controller host or IP address (e.g. 192.168.0.201 or dc1.domain.local)",
    )
    domain: str = Field(
        default="",
        description="AD Domain name (e.g. nks1097.local)",
    )
    port: int = Field(
        default=389,
        description="LDAP (389) or LDAPS (636) port",
    )
    use_ssl: bool = Field(
        default=False,
        description="Use LDAPS (SSL/TLS)",
    )
    tls_validate_cert: bool = Field(
        default=True,
        description="Validate TLS certificates in LDAPS connections (enforces enterprise CA validation)",
    )
    ca_certs_file: Optional[str] = Field(
        default=None,
        description="Optional custom path to CA bundle / certificate file (.pem or .cer) for LDAPS validation",
    )
    username: Optional[str] = Field(
        default=None,
        description="Service account username (DOMAIN\\User or user@domain.local)",
    )
    password: Optional[SecretStr] = Field(
        default=None,
        description="Service account password",
    )
    auth_method: AuthMethod = Field(
        default=AuthMethod.AUTO,
        description="Enterprise Auth: 'windows_integrated' (Kerberos/SSPI - no password), 'credential_manager' (Windows Vault), 'env', or 'auto'",
    )
    credential_target: str = Field(
        default="AD_MCP_CREDENTIAL",
        description="Target entry name in Windows Credential Manager / Vault",
    )
    base_dn: Optional[str] = Field(
        default=None,
        description="Default naming context (e.g. DC=nks1097,DC=local). Auto-detected if omitted.",
    )
    backend: BackendType = Field(
        default=BackendType.HYBRID,
        description="Integration backend: 'hybrid', 'powershell', or 'ldap'",
    )
    timeout_seconds: int = Field(
        default=30,
        description="Execution timeout for LDAP and PowerShell commands",
    )
    max_page_size: int = Field(
        default=1000,
        description="Maximum entries returned in a single query page",
    )

    # Environment & Logging
    audit_log_file: str = Field(
        default="logs/ad_audit.jsonl",
        description="Path to JSON Lines structured audit log file",
    )
    powershell_path: Optional[str] = Field(
        default=None,
        description="Custom path to pwsh or powershell.exe. Auto-detected if null.",
    )
    report_output_dir: str = Field(
        default="reports_output",
        description="Directory where generated reports (HTML, JSON, CSV) will be saved",
    )

    @field_validator("base_dn", mode="before")
    @classmethod
    def compute_base_dn(cls, v: Optional[str], info) -> Optional[str]:
        if v:
            return v
        domain = info.data.get("domain", "")
        if domain:
            parts = [f"DC={p}" for p in domain.strip(".").split(".") if p]
            return ",".join(parts)
        return None

    @property
    def effective_base_dn(self) -> str:
        """Returns configured base_dn or calculates from domain."""
        if self.base_dn:
            return self.base_dn
        if self.domain:
            parts = [f"DC={p}" for p in self.domain.strip(".").split(".") if p]
            return ",".join(parts)
        return ""


# Singleton settings instance
settings = Settings()
