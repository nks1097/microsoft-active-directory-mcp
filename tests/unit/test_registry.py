"""
Unit tests verifying the 100 tools registry.
"""

from ad_mcp.authorization.modes import ActionType
from ad_mcp.tools.registry import registry


def test_registry_contains_exactly_100_tools():
    """Verify that exactly 100 tools are registered in the server."""
    assert registry.count() == 100


def test_each_category_has_10_tools():
    """Verify that each of the 10 categories contains exactly 10 tools."""
    categories = {}
    for tool in registry.list_tools():
        cat = tool.category
        categories[cat] = categories.get(cat, 0) + 1

    assert len(categories) == 10
    for cat, count in categories.items():
        assert count == 10, f"Category {cat.value} has {count} tools, expected 10"


def test_tool_definitions_are_valid():
    """Verify that all tools have valid names, descriptions, and callable handlers."""
    for tool in registry.list_tools():
        assert tool.name.startswith("ad_"), f"Tool {tool.name} must start with 'ad_'"
        assert len(tool.description) > 10, f"Tool {tool.name} description too short"
        assert callable(tool.handler), f"Tool {tool.name} handler must be callable"
        assert tool.action_type in [ActionType.READ, ActionType.WRITE, ActionType.DESTRUCTIVE]


def test_destructive_tools_classification():
    """Verify that critical deletion tools are classified as DESTRUCTIVE."""
    expected_destructive = [
        "ad_delete_user",
        "ad_delete_group",
        "ad_delete_computer",
        "ad_delete_ou",
        "ad_delete_gpo",
        "ad_delete_dns_record",
        "ad_reset_user_password",
    ]
    for name in expected_destructive:
        tool = registry.get_tool(name)
        assert tool is not None, f"Tool {name} should exist"
        assert tool.action_type == ActionType.DESTRUCTIVE, f"Tool {name} should be DESTRUCTIVE"
