# Security and Guardrails Reference

Active Directory is the core identity and access boundary for the enterprise. The Microsoft Active Directory MCP Server implements defense-in-depth controls designed specifically for AI agent integration.

---

## 1. Security Architecture

```
[ AI Agent / LLM ]
         │ (Natural Language Prompt)
         ▼
[ MCP Protocol Layer ]
         │ (Tool Call: Name + Params)
         ▼
┌────────────────────────────────────────────────────────┐
│               SECURITY GATEKEEPER                      │
├────────────────────────────────────────────────────────┤
│ 1. Mode Validation (READ_ONLY / WRITE_APPROVAL / ADMIN) │
│ 2. Critical Object Protection Filter                   │
│ 3. Injection Prevention (LDAP RFC 4515 & PowerShell)  │
│ 4. Single-Use Cryptographic Approval Tokens            │
│ 5. Dry-Run Interception & Change Previews              │
└────────────────────────────────────────────────────────┘
         │ (Sanitized, Authorized Execution)
         ▼
[ PowerShell RSAT / ADSI / LDAPS ]
         │
         ▼
[ Windows Active Directory Domain Controllers ]
```

---

## 2. Protected Critical Objects

When `AD_PROTECT_CRITICAL_OBJECTS=true` (the default), the server blocks write and delete operations targeting:

- **Built-in Administrator**: `Administrator`, `Guest`
- **Kerberos Key Distribution**: `krbtgt`
- **Privileged Administrative Groups**:
  - `Domain Admins`
  - `Enterprise Admins`
  - `Schema Admins`
  - `Administrators`
  - `Account Operators`
  - `Backup Operators`
  - `Server Operators`
  - `Group Policy Creator Owners`
- **Critical Structural Containers**:
  - `OU=Domain Controllers`
  - `CN=System`
  - `CN=Infrastructure`
  - `CN=Configuration`

---

## 3. Cryptographic Approval Token Workflow

In `WRITE_APPROVAL` mode:

1. Agent calls a mutating tool (e.g. `ad_create_user`, `ad_delete_computer`).
2. Server halts execution before touching Active Directory.
3. Server generates an HMAC-SHA256 token tied to:
   - Tool name
   - Target object
   - Exact parameters
   - Expiration timestamp (default: 300 seconds)
4. Server returns a preview:
   ```json
   {
     "success": false,
     "requires_approval": true,
     "confirmation_token": "CONFIRM-A1B2C3D4E5F67890",
     "action_preview": {
       "tool": "ad_create_user",
       "target": "john.doe",
       "expires_in_seconds": 300
     }
   }
   ```
5. Human operator or client confirms by repeating the tool call including `confirmation_token="CONFIRM-A1B2C3D4E5F67890"`.
6. Token is validated and consumed (single-use). Any change in parameters invalidates the token.

---

## 5. Security & Feature Implementation Matrix

| Capability / Feature | Status | Verification & Evidence | Notes |
| :--- | :---: | :--- | :--- |
| **100 Tools Implementation** | `TESTED` | `tests/unit/test_all_tools_mocked.py` (23 tests passing) | Exact 100 functional tools across 10 categories. |
| **Windows Credential Manager (DPAPI)** | `TESTED` | `tests/unit/test_credentials_vault.py` (Real OS CredWrite/CredRead) | Encrypted storage via Windows Local Security Authority. |
| **Centralized READ_ONLY Guard** | `TESTED` | `tests/unit/test_readonly_hard_block.py` | Hard-blocks mutations in both `auth_engine` and `ad_bridge.run_mutation`. |
| **LDAPS TLS Certificate Validation** | `IMPLEMENTED` | `src/ad_mcp/integrations/ldap.py`, `scripts/test_connectivity.ps1` | Enforces `ssl.CERT_REQUIRED`, checks SAN/CN, blocks `CERT_NONE`. |
| **Critical Object Protection** | `TESTED` | `tests/unit/test_guardrails.py` | Prevents deletion of `Domain Admins`, `krbtgt`, `Administrator`, etc. |
| **Approval Tokens (HMAC-SHA256)** | `TESTED` | `tests/unit/test_authorization.py` | Single-use tokens with 300s TTL for `WRITE_APPROVAL` mode. |
| **Audit Logging & Redaction** | `TESTED` | `src/ad_mcp/audit/logger.py` | Masks passwords, tokens, hashes; logs `correlation_id` and operator. |
| **Windows Integrated Auth (SSPI)** | `PARTIAL` | Functional via PowerShell/ADSI bridge under domain user/gMSA | Direct LDAP requires `AD_MCP_CREDENTIAL` or SASL GSSAPI ticket. |
| **AD Recycle Bin Object Restoration** | `NOT_IMPLEMENTED` | Planned for v1.1 | Restoration of tombstoned objects (`Restore-ADObject`). |


Every execution generates an immutable audit record in `logs/ad_audit.jsonl`:

```json
{
  "timestamp": "2026-10-30T10:45:00.123456Z",
  "correlation_id": "c1f7a28e-5b1d-4f1e-9a67-28d08432a688",
  "tool_name": "ad_create_user",
  "operator": "nks1097\\Administrator",
  "server": "192.168.0.201",
  "domain": "nks1097.local",
  "mode": "WRITE_APPROVAL",
  "success": true,
  "execution_time_ms": 142.5,
  "parameters": {
    "sam_account_name": "john.doe",
    "path": "OU=Users,OU=Matriz,DC=nks1097,DC=local",
    "password": "[REDACTED]"
  },
  "error": null,
  "warnings": []
}
```
*Note: Passwords, secrets, and confirmation tokens are always redacted.*

