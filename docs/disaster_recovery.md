# Active Directory Disaster Recovery, Backup & Object Restoration Guide

This document details the disaster recovery architectures, backup procedures, and object restoration mechanisms supported and audited by the Active Directory MCP Server.

---

## 1. Active Directory Recycle Bin (Lixeira do Active Directory)

Introduced in Windows Server 2008 R2 and enhanced in subsequent versions, the **Active Directory Recycle Bin** allows administrators to restore deleted objects (users, groups, computers, OUs) without taking domain controllers offline and without restoring from backup media.

### Key Capabilities
- **Attribute Preservation**: Preserves all object attributes, group memberships, SID history, passwords, and access control lists (ACLs).
- **Deleted State**: Objects remain in the `CN=Deleted Objects` container for the duration of the Deleted Object Lifetime (default: 180 days).

### Enabling the Recycle Bin
The Recycle Bin feature is optional and disabled by default on older domains. To enable it across the entire forest:
```powershell
Enable-ADOptionalFeature 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADForest).RootDomain
```
*(Note: Enabling the Recycle Bin is a permanent, irreversible operation strongly recommended by Microsoft).*

### Restoring Objects
To restore a deleted user or group:
```powershell
# Find deleted user
Get-ADObject -Filter 'isDeleted -eq $true -and name -like "*John*"' -IncludeDeletedObjects

# Restore by ObjectGUID
Restore-ADObject -Identity "a1b2c3d4-e5f6-7890-abcd-ef0123456789"
```

---

## 2. System State Backup & Recovery

Active Directory relies on the **Extensible Storage Engine (ESE / JET)** database located in `NTDS.dit`, the transaction logs (`edb*.log`), and the `SYSVOL` folder.

### Executing a Live System State Backup
On any Active Directory Domain Controller:
```powershell
wbadmin start systemstatebackup -backupTarget:D: -quiet
```

### Tombstone Lifetime & Backup Expiration
- Active Directory enforces a **Tombstone Lifetime (TSL)** (default: 180 days).
- Backups older than the TSL are considered **tombstoned** and **must never be restored** to avoid introducing lingering objects into the directory.

---

## 3. Directory Snapshot Comparison (MCP Tools 91 to 100)

The Active Directory MCP Server provides automated snapshot capture and diff analysis:

- **`ad_generate_domain_inventory`**: Generates a complete baseline JSON snapshot of all domain entities (Users, Groups, OUs, DCs, GPOs, DNS zones).
- **`ad_compare_directory_snapshots`**: Performs high-speed set difference analysis between two temporal snapshots, reporting:
  - Added / removed accounts.
  - Privileged group membership drift (e.g., unauthorized additions to `Domain Admins`).
  - Account property changes (e.g., unexpected activation of `PasswordNeverExpires`).
- **`ad_run_compliance_assessment`**: Audits the directory against standard security baselines:
  - Guest account disabled.
  - Inactive account ratios.
  - Administrator count hygiene.
  - Replication link health.

---

## 4. Disaster Recovery Audit Automation

To verify your environment's disaster recovery readiness at any time:
```powershell
powershell -ExecutionPolicy Bypass -File scripts/test_disaster_recovery.ps1
```

