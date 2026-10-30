# Configuration Reference — Active Directory MCP Server

All configurations are driven by environment variables or an optional `.env` file loaded at startup.

---

## 1. Operational Modes (`AD_MCP_MODE`)

| Mode | Description | Write Operations | Destructive Operations |
| :--- | :--- | :---: | :---: |
| `READ_ONLY` *(Default)* | Read, search, audit, and reporting tools only. Mutating tools are strictly denied. | :x: Blocked | :x: Blocked |
| `WRITE_APPROVAL` | Mutating actions produce an execution preview and require an explicit single-use confirmation token. | :white_check_mark: With Token | :white_check_mark: With Token |
| `FULL_ADMIN` | Direct administrative execution for authorized automated workflows. | :white_check_mark: Direct | :white_check_mark: Direct (Protected objects preserved) |

---

## 2. Complete Environment Variables

| Variable | Type | Default | Description |
| :--- | :---: | :---: | :--- |
| `AD_MCP_MODE` | String | `READ_ONLY` | Server operational mode (`READ_ONLY`, `WRITE_APPROVAL`, `FULL_ADMIN`) |
| `AD_SERVER` | String | `127.0.0.1` | Domain Controller IP or FQDN |
| `AD_DOMAIN` | String | `""` | Active Directory Domain Name (e.g., `corp.contoso.com`) |
| `AD_PORT` | Integer | `389` | LDAP (389) or LDAPS (636) port |
| `AD_USE_SSL` | Boolean | `false` | Enable TLS/SSL encrypted connection |
| `AD_USERNAME` | String | `null` | Service account (`DOMAIN\User` or `user@domain.local`) |
| `AD_PASSWORD` | String | `null` | Service account password (never logged or exposed) |
| `AD_BASE_DN` | String | `null` | Custom Base DN. Auto-detected from domain if omitted |
| `AD_BACKEND` | String | `hybrid` | `hybrid` (PowerShell on Windows, LDAP on Linux), `powershell`, or `ldap` |
| `AD_PROTECT_CRITICAL_OBJECTS` | Boolean | `true` | Prevents deleting/altering Domain Admins, KRBTGT, Domain Controllers |
| `AD_ALLOW_DESTRUCTIVE_OPERATIONS`| Boolean | `false` | Enables deletion commands when allowed by mode |
| `AD_APPROVAL_TOKEN_TTL_SECONDS` | Integer | `300` | Lifetime in seconds for approval tokens (5 minutes) |
| `AD_TIMEOUT_SECONDS` | Integer | `30` | Subprocess and network execution timeout |
| `AD_MAX_PAGE_SIZE` | Integer | `1000` | Maximum results returned in a single query |
| `AD_AUDIT_LOG_FILE` | String | `logs/ad_audit.jsonl`| Path to structured JSON Lines audit log |
| `AD_REPORT_OUTPUT_DIR` | String | `reports_output` | Directory for exported reports (HTML, JSON, CSV) |
| `AD_POWERSHELL_PATH` | String | `null` | Custom path to `pwsh` or `powershell.exe` |

