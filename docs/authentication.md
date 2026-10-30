# Authentication Architecture

The Active Directory MCP Server supports multiple authentication mechanisms depending on host operating system and network topology.

---

## 1. Supported Authentication Methods

| Method | Protocol / Layer | Supported Platforms | Integrity / Security |
| :--- | :---: | :---: | :---: |
| **Windows SSPI (Negotiate)** | PowerShell / .NET DirectoryServices | Windows 10/11, Windows Server | Sign & Seal, Kerberos/NTLMv2 |
| **Kerberos SPNEGO** | GSSAPI / Port 88 | Linux, Windows, macOS | Mutual Authentication, Encrypted |
| **LDAPS (SSL/TLS)** | Direct LDAP over TLS (Port 636) | Cross-Platform | TLS 1.2 / 1.3 Encryption |
| **NTLMv2** | LDAP SASL NTLM (Port 389) | Cross-Platform with pycryptodome | Channel Binding dependent |

---

## 2. Windows SSPI & Kerberos Integrated Authentication

When running on a domain-joined Windows machine with the operator logged in under domain credentials:
- Leave `AD_USERNAME` and `AD_PASSWORD` empty in `.env`.
- The MCP server automatically uses the existing Windows Kerberos token via SSPI!

## 3. Dedicated Service Account with Windows Credential Manager (Zero Plaintext Secrets)

When running with a dedicated service account, never store the password in plaintext:
```ini
AD_SERVER=dc01.corp.contoso.com
AD_DOMAIN=corp.contoso.com
AD_PORT=636
AD_USE_SSL=true
AD_AUTH_METHOD=credential_manager
AD_CREDENTIAL_TARGET=AD_MCP_CREDENTIAL
```
Store the credential once securely via:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/set_production_credentials.ps1
```

The script interactively prompts:
```text
Usuario (ex: CONTOSO\svc_ad_mcp ou svc_ad@corp.contoso.com): CONTOSO\svc_ad_mcp
Senha da conta (a digitacao ficara oculta): **************
```
It securely writes to the Windows Credential Manager (`win32cred.CredWrite`) using `CRED_PERSIST_LOCAL_MACHINE` and Windows DPAPI encryption. In memory, the MCP server calls `win32cred.CredRead` at startup without ever writing the secret to disk.

---

## 4. Environment Variables / Container Secrets (Linux & Docker)

When running on Linux or containerized environments where Windows Credential Manager is not present:
```ini
AD_AUTH_METHOD=env
AD_USERNAME=CONTOSO\svc_ad_mcp
AD_PASSWORD=YourPasswordInEnvOnly
```
Ensure `.env` permissions are restricted to the executing service user (`chmod 600 .env`) or inject secrets directly into memory via Kubernetes Secrets / Docker Compose.

