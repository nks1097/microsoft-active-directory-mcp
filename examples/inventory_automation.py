"""
Example script demonstrating automated inventory collection and compliance audit.
"""

import json

from ad_mcp.tools.reports import ad_generate_domain_inventory, ad_run_compliance_assessment


def run_inventory_audit():
    print("Generating comprehensive Domain Inventory...")
    inventory = ad_generate_domain_inventory(output_format="html")
    print("Inventory result:")
    print(json.dumps(inventory, indent=2))

    print("\nRunning Compliance Assessment...")
    compliance = ad_run_compliance_assessment()
    print("Compliance result:")
    print(json.dumps(compliance, indent=2))


if __name__ == "__main__":
    run_inventory_audit()

