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
git clone https://github.com/your-org/microsoft-active-directory-mcp.git
cd microsoft-active-directory-mcp

# Using uv (fastest):
uv venv --python 3.12
uv sync

# Or using standard python:
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables

Copy `.env.example` to `.env` and fill in your domain details:

```ini
AD_MCP_MODE=READ_ONLY
AD_SERVER=192.168.0.201
AD_DOMAIN=nks1097.local
AD_USERNAME=nks1097\Administrator
AD_PASSWORD=YourSecurePassword
```

### Step 4: Run the MCP Server

```powershell
.\.venv\Scripts\python -m ad_mcp
```

---

## 3. Installation on Linux / macOS (Remote LDAP Mode)

For Linux workstations or containerized deployments querying AD remotely over LDAP/LDAPS:

```bash
git clone https://github.com/your-org/microsoft-active-directory-mcp.git
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

