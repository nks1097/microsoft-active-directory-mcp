# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

Active Directory is a critical identity infrastructure component. We take security vulnerabilities seriously.

**Please DO NOT report security vulnerabilities through public GitHub issues.**

To report a vulnerability:
1. Open a private GitHub Security Advisory in this repository, or
2. Contact the maintainers through the repository security contacts.

Please include:
- Description of the vulnerability.
- Steps to reproduce or proof of concept.
- Affected tool(s) and operational mode (`READ_ONLY`, `WRITE_APPROVAL`, `FULL_ADMIN`).
- Potential impact on Active Directory Domain Services.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation plan within 7 business days.

## Core Security Design Principles

- **Default Read-Only**: The server starts in `READ_ONLY` mode unless explicitly configured otherwise.
- **Write Approval Workflow**: In `WRITE_APPROVAL` mode, mutating operations generate single-use cryptographic tokens with an expiration TTL (default: 5 minutes) and require explicit human operator confirmation.
- **Critical Object Protection**: Built-in protection prevents accidental deletion or modification of critical accounts (e.g., `Administrator`, `krbtgt`, `Domain Admins`, `Enterprise Admins`) and core containers (`OU=Domain Controllers`, `CN=System`).
- **No Password Exposure**: Passwords are never logged in plain text, never returned in tool responses, and securely converted to `SecureString` in memory.
- **Injection Prevention**: All LDAP filters and PowerShell parameters are sanitized and strictly validated against injection. Raw arbitrary script execution from AI models is blocked by design.

