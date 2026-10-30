# Permissions & Least Privilege Delegation

This guide details the minimum Active Directory permissions required for each tool category.

---

## 1. Permission Matrix by Category

| Category | Typical Permissions Required | Recommended Delegation Scope |
| :--- | :--- | :--- |
| **Domain & DCs** | Domain Read (Default Domain Users) | Domain Root (`DC=domain,DC=local`) |
| **Users (Read)** | Read all properties (`objectCategory=person`) | Domain Root or target OUs |
| **Users (Write)** | Create/Delete user objects, Reset password | Target OU only (e.g. `OU=Users,OU=Matriz`) |
| **Groups (Read)** | Read all properties (`objectCategory=group`) | Domain Root |
| **Groups (Write)** | Modify group membership (`member` attribute) | Delegated target Security Groups only |
| **Computers (Read)**| Read all properties (`objectCategory=computer`)| Domain Root |
| **Computers (Write)**| Create/Delete computer objects, Reset account | `OU=Workstations` only |
| **OUs (Management)** | Create/Delete Organizational Units | Parent OU |
| **GPO Management** | Edit Settings, delete, modify security on GPOs| Group Policy Creator Owners (High Privilege) |
| **DNS Server** | DnsAdmins or delegated write to DNS Zone | `DC=DomainDnsZones` |
| **Security & Audit** | Read Security Event Log (Audit policy) | Built-in Event Log Readers group |
| **Replication** | Replicating Directory Changes | Domain Controllers only |

---

## 2. Recommended Delegation Setup via PowerShell

To delegate user management to a service account `svc_ad_mcp` over an OU without granting Domain Admin:

```powershell
$ou = [adsi]"LDAP://OU=Employees,DC=corp,DC=contoso,DC=com"
$identity = "CONTOSO\svc_ad_mcp"

# Grant Reset Password rights
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
    (New-Object System.Security.Principal.NTAccount($identity)),
    [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
    [System.Security.AccessControl.AccessControlType]::Allow,
    [guid]"00299570-246d-11d0-a768-00aa006e0529" # User-Force-Change-Password extended right
)
$ou.ObjectSecurity.AddAccessRule($rule)
$ou.CommitChanges()
```

