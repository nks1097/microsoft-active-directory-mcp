"""
Unit tests proving that no write/mutation operation can execute in READ_ONLY mode.
"""

from ad_mcp.authorization.modes import ActionType
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.config import OperationMode, settings
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.tools.registry import registry


def test_bridge_hard_blocks_mutations_in_read_only():
    """Verify that ad_bridge.run_mutation refuses to execute any script when in READ_ONLY."""
    settings.mcp_mode = OperationMode.READ_ONLY
    success, data, err = ad_bridge.run_mutation("New-ADUser -SamAccountName test")
    assert success is False
    assert "READ_ONLY" in (err or "")


def test_all_write_tools_blocked_by_authorization_engine_in_read_only():
    """Verify that every single WRITE and DESTRUCTIVE tool is rejected by auth_engine in READ_ONLY."""
    settings.mcp_mode = OperationMode.READ_ONLY

    write_tools = [
        t for t in registry.list_tools()
        if t.action_type in (ActionType.WRITE, ActionType.DESTRUCTIVE)
    ]

    assert len(write_tools) > 0

    for tool in write_tools:
        allowed, resp = auth_engine.authorize_execution(tool.name, {})
        assert allowed is False, f"Tool {tool.name} should be blocked in READ_ONLY"
        assert resp is not None
        assert resp.error_code == "MODE_READ_ONLY"
