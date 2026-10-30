"""
Active Directory MCP Server - Secure Credential Setup
Safely prompts for service account credentials and stores them encrypted
in the Windows Credential Manager using the Windows Data Protection API (DPAPI).
"""

import getpass
import sys
from pathlib import Path

# Ensure src/ is on sys.path even if not installed in editable mode
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

try:
    from ad_mcp.auth.credentials import credential_manager
except ImportError as e:
    print(f"ERRO: Nao foi possivel importar ad_mcp: {e}", file=sys.stderr)
    print("Certifique-se de que as dependencias foram instaladas via setup_env.bat ou pip install -r requirements.txt", file=sys.stderr)
    sys.exit(1)

TARGET_NAME = "AD_MCP_CREDENTIAL"

print("==========================================================")
print("   ACTIVE DIRECTORY MCP - CONFIGURACAO DE CREDENCIAIS     ")
print("==========================================================")
print("As credenciais serao gravadas de forma criptografada pelo")
print("Windows (DPAPI) no Cofre do Windows (Credential Manager).")
print("Nenhuma senha sera salva em texto puro em arquivos .env ou json.")
print("==========================================================\n")

print("Digite as credenciais da conta de servico do Active Directory.")
username = input("Usuario (ex: CONTOSO\\svc_ad_mcp ou svc_ad@corp.contoso.com): ").strip()

if not username:
    print("ERRO: O nome de usuario nao pode ser vazio.", file=sys.stderr)
    sys.exit(1)

password = getpass.getpass("Senha da conta (a digitacao ficara oculta): ")

if not password:
    print("ERRO: A senha nao pode ser vazia.", file=sys.stderr)
    sys.exit(1)

try:
    credential_manager.store_in_vault(TARGET_NAME, username, password)
    print("")
    print(f"[SUCESSO] Credencial para '{username}' armazenada no Windows Credential Manager.")
    print(f"Alvo no cofre: {TARGET_NAME}")
    print("Voce NAO precisa colocar senhas no .env ou no mcp_config.json.")
except Exception as ex:
    print(f"\nERRO ao gravar no Cofre do Windows: {ex}", file=sys.stderr)
    sys.exit(2)
