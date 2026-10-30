# Installation Guide — Microsoft Active Directory MCP Server

This guide provides step-by-step instructions for installing and running the Microsoft Active Directory MCP Server across supported platforms.

---

## 1. Prerequisites

- **Python**: Version 3.11, 3.12, or higher.
- **Operating Systems**:
  - **Windows 10 / 11 (64-bit)** with RSAT Active Directory Tools.
  - **Windows Server 2016 / 2019 / 2022 / 2025** (Domain Controller or Member Server).
  - **Linux (Ubuntu, Debian, RHEL)** or **macOS** for remote LDAP/LDAPS queries.
- **Network**: Direct TCP access to Domain Controller ports:
  - Port 389 (LDAP) / 636 (LDAPS).
  - Port 88 (Kerberos).
  - Port 53 (DNS).
  - Port 445 (SMB for SYSVOL/Netlogon).

---

## 2. Installation on Windows Client / Windows Server (Recommended)

Windows environments with PowerShell and RSAT offer full capabilities, including GPO, DNS, replication diagnostics, and native SSPI authentication.

### Step 1: Install RSAT (Remote Server Administration Tools)

Run PowerShell as Administrator and execute:

```powershell
# On Windows 10/11:
Add-WindowsCapability -Online -Name "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
Add-WindowsCapability -Online -Name "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
Add-WindowsCapability -Online -Name "Rsat.Dns.Tools~~~~0.0.1.0"

# On Windows Server:
Install-WindowsFeature -Name RSAT-AD-PowerShell, GPMC, RSAT-DNS-Server
```

Or run the included script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/install_rsat.ps1
```

### Step 2: Clone and Setup Python Environment

```powershell
git clone https://github.com/nks1097/microsoft-active-directory-mcp.git
cd microsoft-active-directory-mcp

# Using uv (fastest):
uv venv --python 3.12
uv sync

# Or using standard python:
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Configure Authentication & Store Passwords Securely

The server supports three authentication methods:

#### Method 1: Windows Credential Vault (Production Recommended — Zero Plaintext Passwords)
This method encrypts your service account credentials directly into the Windows OS Credential Manager using the **Data Protection API (DPAPI)**. No passwords will ever be saved to `.env` or client configuration files.

1. Configure `.env`:
   ```ini
   AD_MCP_MODE=READ_ONLY
   AD_SERVER=dc01.corp.contoso.com
   AD_DOMAIN=corp.contoso.com
   AD_PORT=636
   AD_USE_SSL=true
   AD_TLS_VALIDATE_CERT=true
   AD_AUTH_METHOD=credential_manager
   AD_CREDENTIAL_TARGET=AD_MCP_CREDENTIAL
   ```

2. Store the password encrypted via the setup script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/set_production_credentials.ps1
   ```
   Follow the interactive prompt:
   - **User:** Type your service account (e.g., `CONTOSO\svc_ad_mcp` or `svc_ad@corp.contoso.com`).
   - **Password:** Type the password (typing is masked for privacy).

#### Method 2: Windows Integrated Authentication (SSPI / Kerberos — No Password Needed)
If the server runs on a domain-joined machine under an account that already has Active Directory read access:
1. Configure `.env`:
   ```ini
   AD_AUTH_METHOD=windows_integrated
   ```
2. Leave username and password blank! Windows authenticates seamlessly via Kerberos tickets.

#### Method 3: Direct Environment Variables (Linux, Docker, or CI/CD)
When running on Linux or inside Docker containers where the Windows Vault is not present:
1. Configure `.env` (or pass as container environment variables):
   ```ini
   AD_AUTH_METHOD=env
   AD_USERNAME=CONTOSO\svc_ad_mcp
   AD_PASSWORD=YourPasswordInEnvOnly
   ```

---

### Step 4: Verify Connectivity & Active Directory Bind

Run the diagnostic script to test DNS, port status, and AD bind:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test_connectivity.ps1
```

---

### Step 5: Run the MCP Server

```powershell
.\.venv\Scripts\python -m ad_mcp
```

---

## 3. Installation on Linux / macOS (Remote LDAP Mode)

For Linux workstations or containerized deployments querying AD remotely over LDAP/LDAPS:

```bash
git clone https://github.com/nks1097/microsoft-active-directory-mcp.git
cd microsoft-active-directory-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Set AD_BACKEND=ldap in .env
python3 -m ad_mcp
```

---

## 4. Docker Deployment

```bash
docker build -t ad-mcp .
docker run -it --rm --env-file .env ad-mcp
```

