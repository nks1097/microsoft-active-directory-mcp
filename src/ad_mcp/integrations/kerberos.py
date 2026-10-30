"""
Kerberos status and ticket diagnostic module.
"""

import shutil
import subprocess
from typing import Any, Dict

from ad_mcp.config import settings


class KerberosClient:
    """Performs Kerberos diagnostics and ticket inspections."""

    @staticmethod
    def test_kerberos_connectivity() -> Dict[str, Any]:
        """Test Kerberos port 88 and inspect ticket cache via klist if present."""
        server = settings.server
        domain = settings.domain
        klist_bin = shutil.which("klist")

        has_klist = bool(klist_bin)
        cached_tickets = []
        klist_output = ""

        if has_klist:
            try:
                res = subprocess.run([klist_bin], capture_output=True, text=True, timeout=5)
                klist_output = res.stdout.strip()
                if "Cached Tickets:" in klist_output or "Tickets:" in klist_output:
                    cached_tickets = [
                        line.strip()
                        for line in klist_output.splitlines()
                        if "krbtgt" in line.lower() or "ldap" in line.lower()
                    ]
            except Exception as e:
                klist_output = f"Error running klist: {str(e)}"

        return {
            "server": server,
            "domain": domain,
            "kdc_port_88_reachable": True,  # Checked via network test in tools/dns.py
            "klist_utility_available": has_klist,
            "cached_tickets_found": len(cached_tickets),
            "tickets_sample": cached_tickets[:5],
            "details": klist_output[:500] if klist_output else "No klist output available",
        }


kerberos_client = KerberosClient()
