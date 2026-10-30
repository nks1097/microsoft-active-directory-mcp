"""
Example script demonstrating direct programmatic consumption of AD MCP tools.
"""

import json
from ad_mcp.tools.domain import ad_get_domain_info, ad_get_fsmo_roles
from ad_mcp.tools.users import ad_list_users
from ad_mcp.tools.security import ad_get_locked_accounts, ad_get_domain_admins


def main():
    print("--- 1. Domain Info ---")
    info = ad_get_domain_info()
    print(json.dumps(info, indent=2))

    print("\n--- 2. FSMO Roles ---")
    fsmo = ad_get_fsmo_roles()
    print(json.dumps(fsmo, indent=2))

    print("\n--- 3. Users List (First 5) ---")
    users = ad_list_users(limit=5)
    print(json.dumps(users, indent=2))

    print("\n--- 4. Domain Admins ---")
    admins = ad_get_domain_admins()
    print(json.dumps(admins, indent=2))

    print("\n--- 5. Locked Accounts ---")
    locked = ad_get_locked_accounts()
    print(json.dumps(locked, indent=2))


if __name__ == "__main__":
    main()

