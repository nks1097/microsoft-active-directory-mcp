# LDAPS & TLS Enterprise Configuration Guide

This guide describes how to configure **LDAP over SSL/TLS (LDAPS)** on Microsoft Active Directory Domain Services (TCP port 636) and how to configure the Active Directory MCP Server for strict TLS certificate validation.

---

## 1. How Active Directory Handles LDAPS (Port 636)

By default, when Active Directory Domain Services is installed, Windows Server binds to TCP port 636, but it **will immediately terminate TLS connections** if no valid certificate is installed in the Local Computer's Personal certificate store (`Cert:\LocalMachine\My`).

According to **Microsoft KB 321051**, a valid LDAPS certificate must meet all of the following requirements:
1. Located in the **Local Computer's Personal store** (`Cert:\LocalMachine\My`).
2. Private key present and marked as exportable / accessible by `NTDS` / `SYSTEM`.
3. Enhanced Key Usage (EKU) includes **Server Authentication** (OID `1.3.6.1.5.5.7.3.1`).
4. Subject Name or Subject Alternative Name (SAN) contains the **FQDN of the Domain Controller** (e.g. `dc01.corp.contoso.com`).
5. Chain of trust resolves to a trusted Root Certification Authority on client workstations.

---

## 2. Production Enterprise Setup (Active Directory Certificate Services)

In enterprise environments, LDAPS should be issued by an internal Microsoft Enterprise PKI:

1. **Install AD CS** on a member server or subordinate CA:
   ```powershell
   Install-WindowsFeature AD-Certificate -IncludeManagementTools
   Install-AdcsCertificationAuthority -CAType EnterpriseRootCA
   ```
2. **Automatic Domain Controller Certificate Enrollment**:
   Once an Enterprise CA is online in the forest, all Domain Controllers automatically request and install a certificate using the built-in **Domain Controller** or **Kerberos Authentication** certificate template.
3. **Client Trust**:
   Domain-joined client workstations receive the Enterprise Root CA certificate automatically via Group Policy (`Default Domain Policy`).

---

## 3. Fast Lab / Standalone DC Setup

If you do not have an AD CS Enterprise CA deployed, you can use the automated script included in this repository:

1. Open PowerShell as **Administrator** on the Domain Controller.
2. Run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File scripts/setup_dc_ldaps_certificate.ps1
   ```
3. The script will:
   - Check `Cert:\LocalMachine\My` for existing certificates.
   - Generate a 2048-bit RSA certificate with Server Authentication EKU and appropriate SANs.
   - Install the certificate into `LocalMachine\My` and `LocalMachine\Root`.
   - Export the public certificate to `C:\ad_mcp_ldaps_ca.cer`.

---

## 4. Configuring the Client Workstation Running the MCP Server

On the workstation or server where the Active Directory MCP Server is installed:

### Step 1: Import the Public CA Certificate into Windows Trust Store
```powershell
Import-Certificate -FilePath "C:\ad_mcp_ldaps_ca.cer" -CertStoreLocation Cert:\LocalMachine\Root
```

### Step 2: Configure Environment Variables
In your `.env` file:
```ini
AD_SERVER=dc01.corp.contoso.com
AD_DOMAIN=corp.contoso.com
AD_PORT=636
AD_USE_SSL=true
AD_TLS_VALIDATE_CERT=true
```

> [!IMPORTANT]
> Always configure `AD_SERVER` with the **FQDN** of the Domain Controller (e.g. `dc01.corp.contoso.com`), not its raw IP address, so that TLS hostname and SAN validation succeeds.

### Step 3: Validate Connection
Run the diagnostic script:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test_connectivity.ps1
```
The diagnostic output will confirm:
```text
[3/4] Testando Handshake TLS e Certificado Digital LDAPS (Porta 636)...
  [OK] Handshake TLS estabelecido com sucesso!
       Protocolo: Tls12 / Tls13
       Sujeito:   CN=dc01.corp.contoso.com
       Validade:  ate 2029-10-30
  [OK] A autoridade certificadora (CA) e confiavel nesta maquina.
```

