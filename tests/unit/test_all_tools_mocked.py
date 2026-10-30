"""
Comprehensive test executing all 100 tools with mocked bridge to guarantee
functional execution, schema adherence, and output conformity.
"""

import pytest

from ad_mcp.config import OperationMode, settings
from ad_mcp.integrations.bridge import ad_bridge
from ad_mcp.tools.registry import registry


@pytest.fixture(autouse=True)
def setup_mock_environment(monkeypatch):
    """Mock ad_bridge queries and mutations to return synthetic success responses."""
    settings.mcp_mode = OperationMode.FULL_ADMIN
    settings.protect_critical_objects = False  # Allow testing invocation with sample data

    def mock_run_query(rsat, adsi=None, ldap=None):
        return True, [{"Name": "MockResult", "DistinguishedName": "CN=Mock,DC=test,DC=local"}], None

    def mock_run_mutation(rsat, adsi=None):
        return True, {"Status": "SUCCESS", "Target": "MockTarget"}, None

    monkeypatch.setattr(ad_bridge, "run_query", mock_run_query)
    monkeypatch.setattr(ad_bridge, "run_mutation", mock_run_mutation)


def test_execute_all_100_tools_mocked():
    """Iterate and test execution of each of the 100 tools."""
    tools = registry.list_tools()
    assert len(tools) == 100

    executed = 0
    for t in tools:
        handler = t.handler

        # Minimal valid sample arguments based on tool requirements
        kwargs = {}
        if "identity" in handler.__code__.co_varnames:
            kwargs["identity"] = "MockIdentity"
        if "sam_account_name" in handler.__code__.co_varnames:
            kwargs["sam_account_name"] = "MockUser"
        if "name" in handler.__code__.co_varnames:
            kwargs["name"] = "MockName"
        if "path" in handler.__code__.co_varnames:
            kwargs["path"] = "OU=Test,DC=test,DC=local"
        if "zone_name" in handler.__code__.co_varnames:
            kwargs["zone_name"] = "test.local"
        if "ou_distinguished_name" in handler.__code__.co_varnames:
            kwargs["ou_distinguished_name"] = "OU=Test,DC=test,DC=local"
        if "group" in handler.__code__.co_varnames:
            kwargs["group"] = "MockGroup"
        if "members" in handler.__code__.co_varnames:
            kwargs["members"] = ["User1"]
        if "target_ou" in handler.__code__.co_varnames:
            kwargs["target_ou"] = "OU=Target,DC=test,DC=local"
        if "target_path" in handler.__code__.co_varnames:
            kwargs["target_path"] = "OU=Target,DC=test,DC=local"
        if "target_dn" in handler.__code__.co_varnames:
            kwargs["target_dn"] = "OU=Target,DC=test,DC=local"
        if "gpo_identity" in handler.__code__.co_varnames:
            kwargs["gpo_identity"] = "Default Domain Policy"
        if "gpo_a" in handler.__code__.co_varnames:
            kwargs["gpo_a"] = "GPO1"
            kwargs["gpo_b"] = "GPO2"
        if "query" in handler.__code__.co_varnames:
            kwargs["query"] = "test"
        if "new_password" in handler.__code__.co_varnames:
            kwargs["new_password"] = "SecureP@ssw0rd!"
        if "protected" in handler.__code__.co_varnames:
            kwargs["protected"] = True
        if "snapshot_a" in handler.__code__.co_varnames:
            kwargs["snapshot_a"] = {"users": 10}
            kwargs["snapshot_b"] = {"users": 12}

        # Execute tool handler
        res = handler(**kwargs)

        # Assert valid ToolResponse structure
        assert isinstance(res, dict), f"Tool {t.name} must return a dictionary"
        assert "success" in res, f"Tool {t.name} must contain 'success'"
        assert "execution_time_ms" in res, f"Tool {t.name} must contain 'execution_time_ms'"
        executed += 1

    assert executed == 100, f"Expected 100 executed tools, got {executed}"
