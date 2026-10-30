"""
Exhaustive verification test ensuring 100% enforcement of READ_ONLY mode.
Asserts that NO tool among the 100 registered tools can perform mutations or
bypass the authorization barrier when the server operates in READ_ONLY mode.
"""

import inspect
from unittest.mock import patch

from ad_mcp.authorization.modes import ActionType, get_tool_action_type
from ad_mcp.authorization.rbac import auth_engine
from ad_mcp.config import OperationMode, settings
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.tools.registry import registry


def test_registry_contains_100_tools():
    """Verify exact count of 100 tools."""
    assert len(registry._tools) == 100


def test_all_32_mutation_tools_hard_blocked_in_read_only_mode():
    """
    Exhaustively verify that every WRITE and DESTRUCTIVE tool (32 total)
    is strictly blocked by the authorization engine in READ_ONLY mode.
    """
    mutation_tools = []
    read_tools = []

    for name, tool_def in registry._tools.items():
        action = get_tool_action_type(name)
        if action in (ActionType.WRITE, ActionType.DESTRUCTIVE):
            mutation_tools.append(name)
        else:
            read_tools.append(name)

    assert len(mutation_tools) == 32
    assert len(read_tools) == 68

    with patch.object(settings, "mcp_mode", OperationMode.READ_ONLY):
        # 1. Test Authorization Engine barrier
        for tool_name in mutation_tools:
            allowed, resp = auth_engine.authorize_execution(tool_name, {"dummy_key": "val"})
            assert allowed is False, f"Tool '{tool_name}' must NOT be authorized in READ_ONLY mode"
            assert resp is not None
            assert resp.success is False
            assert resp.error_code == "MODE_READ_ONLY"
            assert "READ_ONLY" in resp.error

        # 2. Test Read tools are all allowed through the authorization barrier
        for tool_name in read_tools:
            allowed, resp = auth_engine.authorize_execution(tool_name, {})
            assert allowed is True, f"Read tool '{tool_name}' should be permitted in READ_ONLY mode"
            assert resp is None


def test_bridge_layer_dual_barrier_rejects_mutation_in_read_only():
    """
    Verify that even if an execution somehow bypassed the authorization engine,
    ad_bridge.run_mutation returns failure and blocks when mode is READ_ONLY.
    """
    with patch.object(settings, "mcp_mode", OperationMode.READ_ONLY):
        success, data, err = ad_bridge.run_mutation(
            rsat_script="New-ADUser -SamAccountName evil",
            adsi_fallback="[adsi]...",
        )
        assert success is False
        assert data is None
        assert "READ_ONLY" in str(err)


def test_all_100_tools_invocation_under_read_only():
    """
    Call each of the 32 mutation tools with dynamically populated parameters
    in READ_ONLY mode and assert that ad_bridge.run_mutation is NEVER called.
    """
    with patch.object(settings, "mcp_mode", OperationMode.READ_ONLY):
        with patch.object(ad_bridge, "run_mutation") as mock_bridge_mutation:
            for name, tool_def in registry._tools.items():
                action = get_tool_action_type(name)
                if action in (ActionType.WRITE, ActionType.DESTRUCTIVE):
                    handler = tool_def.handler
                    sig = inspect.signature(handler)
                    dummy_kwargs = {}
                    for param_name, param in sig.parameters.items():
                        if param.default is inspect.Parameter.empty:
                            dummy_kwargs[param_name] = "dummy_test_val"

                    res = handler(**dummy_kwargs)
                    assert res.get("success") is False, f"Tool {name} succeeded when it should be blocked in READ_ONLY!"
                    assert res.get("mode") == "READ_ONLY"
                    assert "READ_ONLY" in res.get("error", "")

            # Ensure run_mutation was NEVER called by any of the 32 mutation tools
            mock_bridge_mutation.assert_not_called()
