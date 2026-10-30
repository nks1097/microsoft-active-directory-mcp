"""
Credential and authentication handling for Active Directory MCP Server.
Supports:
1. Windows Credential Manager / DPAPI Vault (Encrypted OS-level storage - Recommended for Production)
2. Windows Integrated Authentication (Kerberos / SSPI via PowerShell/ADSI bridge)
3. Secure Environment Variables (Memory / Orchestrator injection)
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
        Return username and password securely using configured enterprise auth method.
        Never logs or leaks password strings in exceptions or log records.
        """
        method = settings.auth_method

        # 1. Windows Integrated Authentication (Kerberos / SSPI)
        if method == AuthMethod.WINDOWS_INTEGRATED:
            logger.info("Using Windows Integrated Authentication (Kerberos/SSPI thread token via PowerShell/ADSI bridge).")
            return None, None

        # 2. Windows Credential Manager (Cofre de Credenciais do Windows via DPAPI)
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
                    logger.error(f"Failed to read from Windows Credential Manager target '{settings.credential_target}'")
                    raise RuntimeError(
                        f"Target '{settings.credential_target}' nao encontrado no Cofre do Windows. "
                        "Execute o script 'scripts/set_production_credentials.ps1' para registrar a credencial criptografada."
                    ) from e

        # 3. Environment Variables fallback (Memory / Container Secrets)
        user = settings.username
        password = settings.password.get_secret_value() if settings.password else None
        if user and password:
            return user, password

        # 4. Default fallback: Windows Integrated Authentication (SSPI/Kerberos)
        logger.info("No explicit credentials configured. Defaulting to Windows Integrated Authentication (SSPI/Kerberos).")
        return None, None

    @staticmethod
    def store_in_vault(target: str, username: str, password: str) -> bool:
        """
        Store credentials encrypted into Windows Credential Manager using DPAPI.
        Validates non-empty input and binds to the current Windows user profile.
        """
        if not WIN32CRED_AVAILABLE:
            raise RuntimeError("A biblioteca win32cred nao esta disponivel no ambiente.")

        if not target or not isinstance(target, str):
            raise ValueError("O identificador do alvo (target) nao pode ser vazio.")
        if not username or not isinstance(username, str):
            raise ValueError("O nome de usuario nao pode ser vazio.")
        if not password or not isinstance(password, str):
            raise ValueError("A senha nao pode ser vazia.")

        # Sanitiza barra dupla se fornecida pelo usuario
        clean_user = username.replace("\\\\", "\\") if "\\\\" in username else username

        try:
            win32cred.CredWrite(
                {
                    "Type": win32cred.CRED_TYPE_GENERIC,
                    "TargetName": target,
                    "UserName": clean_user,
                    "CredentialBlob": password,
                    "Persist": win32cred.CRED_PERSIST_LOCAL_MACHINE,
                },
                0,
            )
            return True
        except Exception as e:
            logger.error(f"Erro ao gravar credencial no Windows Credential Manager para target '{target}'")
            raise RuntimeError(f"Falha na API win32cred.CredWrite: {str(e)}") from None

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
