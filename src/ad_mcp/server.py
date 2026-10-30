"""
Server module for Microsoft Active Directory MCP.
Exposes 100 administrative, auditing, and diagnostic tools to AI agents via MCP.
"""

import logging
import sys

from mcp.server.mcpserver import MCPServer

from ad_mcp.config import settings
from ad_mcp.tools.registry import registry

logger = logging.getLogger("ad_mcp.server")


def create_mcp_server() -> MCPServer:
    """Initialize and configure the Active Directory MCP Server with 100 tools."""
    server = MCPServer("Microsoft Active Directory MCP Server")

    # Register all 100 tools from registry
    for tool_def in registry.list_tools():
        server.tool(
            name=tool_def.name,
            description=f"[{tool_def.category.value}] [{tool_def.action_type.value}] {tool_def.description}",
        )(tool_def.handler)

    return server


# Global server instance
mcp_server = create_mcp_server()


def print_startup_banner() -> None:
    """Print informative operational banner to stderr (keeps stdout clean for stdio transport)."""
    banner = f"""
========================================================================
    MICROSOFT ACTIVE DIRECTORY MCP SERVER — 100 ESSENTIAL TOOLS
========================================================================
 Target Domain:        {settings.domain or "(Not specified)"}
 Target DC Server:     {settings.server}
 Port / SSL:           {settings.port} (SSL: {settings.use_ssl})
 Operational Mode:     {settings.mcp_mode.value}
 Protected Objects:    {settings.protect_critical_objects}
 Integration Backend:  {settings.backend.value}
 Total Tools Loaded:   {registry.count()} / 100
 Audit Log:            {settings.audit_log_file}
========================================================================
 Server running in {settings.mcp_mode.value} mode.
"""
    sys.stderr.write(banner)
    sys.stderr.flush()


def run_stdio() -> None:
    """Run the MCP server over standard I/O."""
    print_startup_banner()
    mcp_server.run()


if __name__ == "__main__":
    run_stdio()
