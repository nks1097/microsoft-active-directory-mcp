# Production Deployment & Best Practices

Guidelines for deploying the Microsoft Active Directory MCP Server in enterprise production environments.

---

## 1. Principle of Least Privilege (Service Account Delegation)

Never use the built-in domain `Administrator` account in production! Instead, create a dedicated Managed Service Account (gMSA) or standard service account with delegated permissions:

1. **For Read-Only / Auditor Agents:**
   - Add the service account to the built-in `Domain Users` or `Auditors` group.
   - Do NOT grant domain admin rights.
   - Set `AD_MCP_MODE=READ_ONLY`.

2. **For User Helpdesk Automation:**
   - Delegate rights only to specific OUs (e.g., `OU=StandardUsers,DC=corp,DC=com`):
     - Reset password
     - Read and write user account restrictions
     - Unlock user accounts
   - Set `AD_MCP_MODE=WRITE_APPROVAL`.

3. **For Computer Management:**
   - Delegate rights to join or manage objects in `OU=Workstations`.

---

## 2. Hardening Network Communications

- **Always use LDAPS (TCP 636) in production**:
  - Install a trusted Enterprise Root CA certificate on the server running the MCP.
  - Set `AD_USE_SSL=true` and `AD_PORT=636`.
- **Restrict Network Access (Firewall)**:
  - Allow outbound connections from the MCP host to Domain Controllers on required ports only (88, 389, 636, 53, 445).

---

## 3. Auditing and SIEM Ingestion

The MCP server writes JSON Lines structured logs to `logs/ad_audit.jsonl`. Configure your SIEM forwarder (e.g., Splunk Universal Forwarder, Elastic Filebeat, Microsoft Sentinel agent, or Wazuh) to monitor this file:

```yaml
# Example Filebeat input:
filebeat.inputs:
- type: filestream
  id: ad-mcp-audit
  paths:
    - /path/to/microsoft-active-directory-mcp/logs/*.jsonl
  json.keys_under_root: true
```

---

## 4. Disaster Recovery & Rollback

Before executing wide-scale administrative changes:
- Run with `dry_run=true` to preview the modifications.
- Generate an inventory snapshot using `ad_generate_domain_inventory`.
- Ensure Active Directory Recycle Bin is enabled (`Enable-ADOptionalFeature 'Recycle Bin Feature'`).

