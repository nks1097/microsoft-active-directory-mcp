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

## 3. Dedicated Service Account (Remote / Non-Domain Hosts)

When running from a standalone machine (such as a developer workstation or container):
```ini
AD_SERVER=192.168.0.201
AD_DOMAIN=nks1097.local
AD_USERNAME=nks1097\svc_ad_mcp
AD_PASSWORD=YourStrongServiceAccountPassword
```
The server will construct an authenticated session using either SecureString credentials via PowerShell or SASL/NTLM/LDAPS over LDAP.

